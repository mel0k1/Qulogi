package engine

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mel0k1/qulogi/internal/tunnel"
	"github.com/mel0k1/qulogi/internal/turnrelay"
)

// TestTunnelLevelOverTurn checks the transport stack under the engine:
// tunnel.Client carried by a TURN allocation against the reference
// server, then the same path through the engine dialer and the SOCKS5
// listener.
func TestTunnelLevelOverTurn(t *testing.T) {
	psk := "turn-psk"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "TUNNEL_VIA_TURN_OK")
	}))
	defer target.Close()

	relay := startRelay(t, psk)
	turnAddr := startTurnRelay(t, relay)

	cl := &tunnel.Client{
		Server: relay,
		PSK:    []byte(psk),
		Conn: func() (net.Conn, error) {
			return (&turnrelay.Client{Server: turnAddr}).Dial(relay)
		},
	}
	addr, err := tunnel.ParseAddress(strings.TrimPrefix(target.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := cl.Dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "TUNNEL_VIA_TURN_OK") {
		t.Fatalf("body: %q", string(buf[:n]))
	}
	_ = c.Close()

	// The full engine path: dialer and SOCKS5 listener.
	e := New(Config{
		Mode:       ModeTunnel,
		Listen:     "127.0.0.1:0",
		Server:     relay,
		PSK:        psk,
		TURNServer: turnAddr,
		Log:        func(msg string) { t.Log("engine:", msg) },
	})
	if err := e.Start(); err != nil {
		t.Fatalf("engine start: %v", err)
	}
	defer e.Stop()
	body := socks5Fetch(t, e.Status().Listen, strings.TrimPrefix(target.URL, "http://"))
	if !strings.Contains(body, "TUNNEL_VIA_TURN_OK") {
		t.Fatalf("socks5 body: %q", body)
	}
}
