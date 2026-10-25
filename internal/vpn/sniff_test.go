package vpn

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mel0k1/qulogi/internal/transport"
)

// dialRecord captures what serveTCP asked the dialer to do.
type dialRecord struct {
	via string
}

// stackFor builds a bare Stack around the given config (same package, so
// serveTCP is reachable without a TUN device).
func stackFor(cfg Config) *Stack {
	s := &Stack{cfg: cfg}
	s.ctx = context.Background()
	return s
}

func TestServeTCPDirectBySNI(t *testing.T) {
	app, client := net.Pipe()
	up, server := net.Pipe()

	var rec dialRecord
	var mu sync.Mutex
	cfg := Config{
		RouteSNI: func(sni, dst string) string {
			if sni == "blocked.example" {
				return "tunnel"
			}
			return "direct"
		},
		DialVia: func(ctx context.Context, network, addr, via string) (net.Conn, error) {
			mu.Lock()
			rec.via = via
			mu.Unlock()
			return up, nil
		},
	}
	s := stackFor(cfg)
	done := make(chan struct{})
	go func() {
		s.serveTCP(client, "203.0.113.7:443")
		close(done)
	}()

	// The app opens with a TLS ClientHello for a non-whitelisted name.
	hello := transport.BuildClientHello("blocked.example")
	if _, err := app.Write(hello); err != nil {
		t.Fatal(err)
	}
	go func() { // async: net.Pipe is synchronous, serveTCP replays first
		app.Write([]byte("more-plain-data"))
	}()

	// serveTCP must have replayed the sniffed prefix upstream (read at
	// the far end of the pipe).
	head := make([]byte, len(hello))
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := readFull(server, head); err != nil {
		t.Fatalf("prefix replay: %v", err)
	}
	if string(head) != string(hello) {
		t.Fatal("prefix mismatch")
	}
	mu.Lock()
	via := rec.via
	mu.Unlock()
	if via != "tunnel" {
		t.Fatalf("via = %q, want tunnel", via)
	}

	// The rest of the flow must splice through.
	tail := "more-plain-data"
	buf := make([]byte, len(tail))
	if _, err := readFull(server, buf); err != nil {
		t.Fatalf("tail: %v", err)
	}
	if string(buf) != tail {
		t.Fatalf("tail content %q", buf)
	}
	_ = app.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := server.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := readFull(app, resp); err != nil {
		t.Fatalf("server->app: %v", err)
	}
	if string(resp) != "ok" {
		t.Fatalf("resp %q", resp)
	}
	client.Close()
	up.Close()
	server.Close()
	app.Close()
	<-done
}

func TestServeTCPDrop(t *testing.T) {
	app, client := net.Pipe()
	dialed := false
	cfg := Config{
		RouteSNI: func(sni, dst string) string {
			if sni == "evil.example" {
				return "drop"
			}
			return "direct"
		},
		DialVia: func(ctx context.Context, network, addr, via string) (net.Conn, error) {
			dialed = true
			return nil, net.ErrClosed
		},
	}
	s := stackFor(cfg)
	done := make(chan struct{})
	go func() {
		s.serveTCP(client, "198.51.100.9:443")
		close(done)
	}()
	if _, err := app.Write(transport.BuildClientHello("evil.example")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("serveTCP did not return after drop")
	}
	if dialed {
		t.Fatal("dropped flow must not be dialed")
	}
	app.Close()
	client.Close()
}

func TestServeTCPNonTLSFallback(t *testing.T) {
	app, client := net.Pipe()
	up, server := net.Pipe()
	defer up.Close()
	defer server.Close()

	var gotSNI string
	var mu sync.Mutex
	cfg := Config{
		RouteSNI: func(sni, dst string) string {
			mu.Lock()
			gotSNI = sni
			mu.Unlock()
			if dst == "93.184.216.34:80" {
				return "direct"
			}
			return "tunnel"
		},
		DialVia: func(ctx context.Context, network, addr, via string) (net.Conn, error) {
			return up, nil
		},
	}
	s := stackFor(cfg)
	done := make(chan struct{})
	go func() {
		s.serveTCP(client, "93.184.216.34:80")
		close(done)
	}()
	if _, err := app.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	// The prefix (the plaintext request) must be replayed upstream.
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	buf := make([]byte, len(request))
	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := readFull(server, buf); err != nil {
		t.Fatalf("prefix replay: %v", err)
	}
	if string(buf) != string(request) {
		t.Fatalf("prefix content %q", buf)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("serveTCP stuck on non-TLS flow")
	}
	mu.Lock()
	sni := gotSNI
	mu.Unlock()
	if sni != "" {
		t.Fatalf("sni = %q, want empty for plaintext", sni)
	}
	app.Close()
	client.Close()
	up.Close()
}

func TestSniffTimesOutSilentApp(t *testing.T) {
	app, client := net.Pipe()
	defer app.Close()
	defer client.Close()
	s := stackFor(Config{})
	start := time.Now()
	go func() {
		time.Sleep(3 * time.Second)
		app.Write([]byte("SSH-2.0-x\r\n")) // arrives after the sniff window
	}()
	data, sni := s.sniff(client)
	if sni != "" {
		t.Fatalf("sni = %q", sni)
	}
	elapsed := time.Since(start)
	if elapsed < 800*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("sniff window: %v, want ~1s", elapsed)
	}
	if len(data) != 0 {
		t.Fatalf("expected empty prefix, got %d bytes", len(data))
	}
	// In serveTCP the connection keeps flowing after the window: the late
	// banner must still be readable.
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 11)
	if _, err := readFull(client, buf); err != nil {
		t.Fatalf("late data lost: %v", err)
	}
	if string(buf) != "SSH-2.0-x\r\n" {
		t.Fatalf("late data: %q", buf)
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
