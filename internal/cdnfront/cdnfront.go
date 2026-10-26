// Package cdnfront implements the cdn-front transport class from
// docs/RELAY_DISCOVERY.md (M4): the client opens TLS to the edge of a
// whitelisted CDN while the inner HTTP request carries the Host of a relay
// parked behind the same CDN.
//
//	device ──TLS(SNI: белый домен)──► CDN edge ──Host: relay──► origin (qulogid)
//
// The filter sees a connection to an allowed CDN address with an allowed
// SNI; the CDN routes by the Host header, which it does not cross-check
// against SNI (the working condition of this transport). The tunnel rides
// an HTTP/1.1 Upgrade, so both directions stay streaming:
//
//	GET /qulogi HTTP/1.1
//	Host: relay.example.net
//	Upgrade: qulogi/1
//	Connection: Upgrade
//
//	HTTP/1.1 101 Switching Protocols
//	Upgrade: qulogi/1
//
// After the switch the raw byte stream is exactly the tunnel protocol
// (salt handshake, address header, TCP stream or framed UDP datagrams).
package cdnfront

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultPath is the tunnel endpoint both sides agree on.
const DefaultPath = "/qulogi"

// Front dials the relay through a CDN edge (client side).
type Front struct {
	// EdgeAddr is the CDN edge the filter allows: host:port.
	EdgeAddr string
	// EdgeSNI is the whitelisted hostname claimed in the TLS handshake.
	EdgeSNI string
	// Host is the relay hostname behind the same CDN; the CDN routes by
	// this Host header to the origin.
	Host string
	// Path is the tunnel endpoint (default /qulogi).
	Path string
	// InsecureSkipVerify skips the edge certificate verification. For
	// tests and self-signed edge pins; production keeps WebPKI.
	InsecureSkipVerify bool
	// Timeout bounds dial + TLS + upgrade (default 10s).
	Timeout time.Duration
}

// Dial connects through the CDN and returns the raw tunnel stream.
func (f Front) Dial() (net.Conn, error) {
	timeout := f.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	path := f.Path
	if path == "" {
		path = DefaultPath
	}
	if f.EdgeAddr == "" || f.Host == "" {
		return nil, errors.New("cdnfront: edge addr and host are required")
	}
	sni := f.EdgeSNI
	if sni == "" {
		sni = f.Host
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", f.EdgeAddr, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: f.InsecureSkipVerify,
	})
	if err != nil {
		return nil, fmt.Errorf("cdnfront: edge %s: %w", f.EdgeAddr, err)
	}

	req := strings.Join([]string{
		"GET " + path + " HTTP/1.1",
		"Host: " + f.Host,
		"Upgrade: qulogi/1",
		"Connection: Upgrade",
		"User-Agent: Qulogi/0.4 (+https://github.com/mel0k1/Qulogi)",
		"", "",
	}, "\r\n")
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("cdnfront: upgrade request: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("cdnfront: upgrade response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		msg, _ := parseErrBody(resp)
		conn.Close()
		return nil, fmt.Errorf("cdnfront: edge refused upgrade: http %d %s", resp.StatusCode, msg)
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Upgrade")), "qulogi") {
		conn.Close()
		return nil, errors.New("cdnfront: edge did not confirm the qulogi upgrade")
	}
	return &bufferedConn{Conn: conn, r: br}, nil
}

// parseErrBody extracts a short human readable reason from a refusal.
func parseErrBody(resp *http.Response) (string, error) {
	buf := make([]byte, 256)
	n, err := resp.Body.Read(buf)
	if n == 0 && err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

// Serve accepts tunnel sessions arriving as HTTP Upgrades on an HTTP
// listener (behind the CDN the origin usually serves plain HTTP; the CDN
// terminates TLS). A plausible index page masks the endpoint.
type Server struct {
	Listener net.Listener
	PSK      []byte
	// Path is the tunnel endpoint (default /qulogi).
	Path string
	Log  func(string)
}

// handler returns the HTTP surface of the front (index page + tunnel).
func (s *Server) handler() http.Handler {
	path := s.Path
	if path == "" {
		path = DefaultPath
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc(path, s.handleTunnel)
	return mux
}

// ServeHTTP lets the front be embedded into any HTTP server (tests,
// custom TLS termination, an existing mux on the origin).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler().ServeHTTP(w, r)
}

// Serve runs until the listener fails.
func (s *Server) Serve() error {
	srv := &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 15 * time.Second,
	}
	return srv.Serve(s.Listener)
}

func (s *Server) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log(fmt.Sprintf(format, args...))
	}
}

func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	switch {
	case strings.Contains(upgrade, "websocket"):
		s.handleWS(w, r)
	case strings.Contains(upgrade, "qulogi"):
		s.handleLegacyUpgrade(w, r)
	default:
		http.Error(w, "qulogi tunnel endpoint", http.StatusMisdirectedRequest)
	}
}

// handleWS accepts an RFC 6455 upgrade (real CDN edges).
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing websocket key", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "upgrade unsupported", http.StatusInternalServerError)
		return
	}
	conn, br, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	resp := strings.Join([]string{
		"HTTP/1.1 101 Switching Protocols",
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Accept: " + wsAcceptValue(key),
		"Sec-WebSocket-Protocol: qulogi",
		"", "",
	}, "\r\n")
	if _, err := conn.Write([]byte(resp)); err != nil {
		return
	}
	s.serveTunnel(conn, br.Reader, r, true)
}

// handleLegacyUpgrade keeps the pre-0.6 bare qulogi switch working.
func (s *Server) handleLegacyUpgrade(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "upgrade unsupported", http.StatusInternalServerError)
		return
	}
	conn, br, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	resp := strings.Join([]string{
		"HTTP/1.1 101 Switching Protocols",
		"Upgrade: qulogi/1",
		"Connection: Upgrade",
		"", "",
	}, "\r\n")
	if _, err := conn.Write([]byte(resp)); err != nil {
		return
	}
	s.serveTunnel(conn, br.Reader, r, false)
}

// serveTunnel hands a switched stream to the tunnel acceptor; with ws
// the stream carries WebSocket binary frames.
func (s *Server) serveTunnel(conn net.Conn, br *bufio.Reader, r *http.Request, ws bool) {
	s.logf("cdn-front session from %s (host %s)", conn.RemoteAddr(), r.Host)
	logFn := func(msg string) { s.logf("%s", msg) }
	wrapped := &bufferedConn{Conn: conn, r: br}
	var stream net.Conn = wrapped
	if ws {
		stream = newWSServerStream(wrapped)
	}
	if err := accept(stream, nil, s.PSK, logFn); err != nil {
		s.logf("cdn-front session %s: %v", conn.RemoteAddr(), err)
	}
}

// handleIndex serves a small plausible page for curious probes.
func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(indexPage))
}

const indexPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Service</title></head>
<body><h1>It works</h1><p>This host hosts a content delivery endpoint.</p></body></html>
`
