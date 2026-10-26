package cdnfront

// RFC 6455 layer: real CDNs proxy only WebSocket upgrades, so the tunnel
// rides binary frames when fronting through a real CDN network. Client
// frames are masked as the RFC demands — edges drop unmasked traffic.

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	wsGUID       = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wsMaxMessage = 16 << 20
)

func wsAcceptValue(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// wsStream is a net.Conn over WebSocket binary frames. client=true masks
// outgoing frames and expects unmasked inbound ones; server-side is the
// reverse.
type wsStream struct {
	conn   net.Conn
	client bool

	wmu sync.Mutex

	fin    bool
	rbuf   []byte
	rframe []byte
}

func newWSClientStream(conn net.Conn) *wsStream { return &wsStream{conn: conn, client: true} }
func newWSServerStream(conn net.Conn) *wsStream { return &wsStream{conn: conn} }

func (w *wsStream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(w.rbuf) > 0 {
		n := copy(b, w.rbuf)
		w.rbuf = w.rbuf[n:]
		return n, nil
	}
	for {
		payload, opcode, err := w.readFrame()
		if err != nil {
			return 0, err
		}
		switch opcode {
		case 0x2, 0x0: // binary / continuation
			if len(w.rframe)+len(payload) > wsMaxMessage {
				return 0, errors.New("cdnfront: websocket message too large")
			}
			w.rframe = append(w.rframe, payload...)
			if w.fin {
				w.rbuf = w.rframe
				w.rframe = nil
				n := copy(b, w.rbuf)
				w.rbuf = w.rbuf[n:]
				return n, nil
			}
		case 0x8: // close
			_ = w.writeControl(0x8, []byte{0x03, 0xe8})
			return 0, io.EOF
		case 0x9: // ping — reply off the data path
			go func() { _ = w.writeControl(0xA, payload) }()
		case 0xA: // pong
		default:
			return 0, fmt.Errorf("cdnfront: unexpected websocket opcode 0x%x", opcode)
		}
	}
}

func (w *wsStream) writeFrame(opcode byte, payload []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	var hdr [14]byte
	hdr[0] = 0x80 | opcode
	n := 1
	switch {
	case len(payload) < 126:
		hdr[1] = byte(len(payload))
		n = 2
	case len(payload) <= 0xFFFF:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(payload)))
		n = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(len(payload)))
		n = 10
	}
	if w.client {
		hdr[1] |= 0x80
		if _, err := rand.Read(hdr[n : n+4]); err != nil {
			return err
		}
		n += 4
	}
	if _, err := w.conn.Write(hdr[:n]); err != nil {
		return err
	}
	if !w.client {
		_, err := w.conn.Write(payload)
		return err
	}
	mk := hdr[n-4 : n]
	buf := make([]byte, len(payload))
	for i, c := range payload {
		buf[i] = c ^ mk[i%4]
	}
	_, err := w.conn.Write(buf)
	return err
}

func (w *wsStream) writeControl(opcode byte, payload []byte) error {
	if len(payload) > 125 {
		payload = payload[:125]
	}
	return w.writeFrame(opcode, payload)
}

func (w *wsStream) Write(b []byte) (int, error) {
	if err := w.writeFrame(0x2, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wsStream) Close() error {
	// Never let the closing handshake park on a dead connection.
	_ = w.conn.SetWriteDeadline(time.Now().Add(time.Second))
	_ = w.writeControl(0x8, []byte{0x03, 0xe8})
	return w.conn.Close()
}

func (w *wsStream) LocalAddr() net.Addr                { return w.conn.LocalAddr() }
func (w *wsStream) RemoteAddr() net.Addr               { return w.conn.RemoteAddr() }
func (w *wsStream) SetDeadline(t time.Time) error      { return w.conn.SetDeadline(t) }
func (w *wsStream) SetReadDeadline(t time.Time) error  { return w.conn.SetReadDeadline(t) }
func (w *wsStream) SetWriteDeadline(t time.Time) error { return w.conn.SetWriteDeadline(t) }

func (w *wsStream) readFrame() ([]byte, byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(w.conn, hdr[:]); err != nil {
		return nil, 0, err
	}
	fin := hdr[0]&0x80 != 0
	opcode := hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(w.conn, ext[:]); err != nil {
			return nil, 0, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(w.conn, ext[:]); err != nil {
			return nil, 0, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > wsMaxMessage {
		return nil, 0, errors.New("cdnfront: websocket frame too large")
	}
	var mk [4]byte
	if masked {
		if _, err := io.ReadFull(w.conn, mk[:]); err != nil {
			return nil, 0, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(w.conn, payload); err != nil {
		return nil, 0, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mk[i%4]
		}
	}
	w.fin = fin
	return payload, opcode, nil
}

// WSFront dials the relay through a real CDN with an RFC 6455 upgrade.
type WSFront struct {
	// EdgeAddr is the CDN edge (host or host:port); for same-host camo
	// it is the relay hostname itself.
	EdgeAddr string
	// EdgeSNI is the TLS SNI; default Host.
	EdgeSNI string
	// Host is the relay origin hostname routed by the CDN.
	Host string
	// Path is the tunnel endpoint (default /qulogi).
	Path string
	// InsecureSkipVerify skips edge certificate verification (tests).
	InsecureSkipVerify bool
	// Timeout bounds dial + TLS + upgrade (default 10s).
	Timeout time.Duration
	// Dialer overrides the TCP dial (tests).
	Dialer func(network, addr string) (net.Conn, error)
}

// Dial connects through the CDN and returns the tunnel stream. A legacy
// front confirming the bare qulogi upgrade keeps working (raw stream).
func (f WSFront) Dial() (net.Conn, error) {
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
	addr := f.EdgeAddr
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}

	var raw net.Conn
	var err error
	if f.Dialer != nil {
		raw, err = f.Dialer("tcp", addr)
	} else {
		raw, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return nil, fmt.Errorf("cdnfront: edge %s: %w", addr, err)
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: f.InsecureSkipVerify,
		NextProtos:         []string{"http/1.1"},
	})
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("cdnfront: edge %s tls: %w", addr, err)
	}

	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		raw.Close()
		return nil, err
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)
	req := strings.Join([]string{
		"GET " + path + " HTTP/1.1",
		"Host: " + f.Host,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Key: " + keyB64,
		"Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Protocol: qulogi",
		"User-Agent: Qulogi/0.6 (+https://github.com/mel0k1/Qulogi)",
		"", "",
	}, "\r\n")
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("cdnfront: ws handshake request: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("cdnfront: ws handshake response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		msg, _ := parseErrBody(resp)
		conn.Close()
		return nil, fmt.Errorf("cdnfront: edge refused ws upgrade: http %d %s", resp.StatusCode, msg)
	}
	upgrade := strings.ToLower(resp.Header.Get("Upgrade"))
	if strings.Contains(upgrade, "qulogi") {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	if !strings.Contains(upgrade, "websocket") || resp.Header.Get("Sec-WebSocket-Accept") != wsAcceptValue(keyB64) {
		conn.Close()
		return nil, errors.New("cdnfront: edge did not confirm the websocket upgrade")
	}
	_ = conn.SetDeadline(time.Time{})
	return newWSClientStream(&bufferedConn{Conn: conn, r: br}), nil
}
