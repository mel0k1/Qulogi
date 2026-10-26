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

const DefaultPath = "/qulogi"

// Front dials the relay through a CDN edge.
type Front struct {
	EdgeAddr           string
	EdgeSNI            string
	Host               string
	Path               string
	InsecureSkipVerify bool
	Timeout            time.Duration
}

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

func parseErrBody(resp *http.Response) (string, error) {
	buf := make([]byte, 256)
	n, err := resp.Body.Read(buf)
	if n == 0 && err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

// Serve accepts tunnel sessions arriving as HTTP Upgrades.
type Server struct {
	Listener net.Listener
	PSK      []byte
	Path     string
	Log      func(string)
}

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

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler().ServeHTTP(w, r)
}

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

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(indexPage))
}

const indexPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Service</title></head>
<body><h1>It works</h1><p>This host hosts a content delivery endpoint.</p></body></html>
`
