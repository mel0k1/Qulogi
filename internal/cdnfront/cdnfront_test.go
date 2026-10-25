package cdnfront

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mel0k1/qulogi/internal/tunnel"
)

func TestFrontEndToEnd(t *testing.T) {
	const psk = "owl-front"

	// The "CDN edge" terminates TLS and routes by Host to the tunnel
	// front (in production the edge forwards to the qulogid origin; for
	// the client the two are indistinguishable). A wrong Host is refused
	// like a real CDN would.
	front := &Server{PSK: []byte(psk)}
	edge := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "relay.example.net" {
			http.Error(w, "unknown host", http.StatusNotFound)
			return
		}
		front.ServeHTTP(w, r)
	}))
	defer edge.Close()

	// TCP echo target on the "internet".
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	f := &Front{
		EdgeAddr:           edge.Listener.Addr().String(),
		EdgeSNI:            "white.cdn.example",
		Host:               "relay.example.net",
		InsecureSkipVerify: true, // the fake edge uses a self-signed cert
	}

	client := &tunnel.Client{PSK: []byte(psk), Conn: f.Dial}
	echoPort := uint16(ln.Addr().(*net.TCPAddr).Port)

	t.Run("tcp stream", func(t *testing.T) {
		session, err := client.Dial(tunnel.Address{Host: "127.0.0.1", Port: echoPort})
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		if err := session.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		msg := []byte("hello through the cdn front")
		for i := 0; i < 2; i++ {
			if _, err := session.Write(msg); err != nil {
				t.Fatalf("write %d: %v", i, err)
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(session, got); err != nil {
				t.Fatalf("read %d: %v", i, err)
			}
			if string(got) != string(msg) {
				t.Fatalf("round %d: %q", i, got)
			}
		}
	})

	t.Run("udp datagrams", func(t *testing.T) {
		udpEcho := udpEchoServer(t)
		up, err := client.DialUDP(tunnel.Address{Host: "127.0.0.1", Port: uint16(udpEcho.Port)})
		if err != nil {
			t.Fatal(err)
		}
		defer up.Close()
		if err := up.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		for _, msg := range [][]byte{[]byte("dg-1"), make([]byte, 1200)} {
			if _, err := up.Write(msg); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(up, got); err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != string(msg) {
				t.Fatalf("datagram mismatch")
			}
		}
	})
}

// udpEcho answers every datagram with the same payload.
func udpEchoServer(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := conn.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr)
}

func TestIndexPageMasksEndpoint(t *testing.T) {
	front := &Server{PSK: []byte("x")}
	srv := httptest.NewServer(front)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("index: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Fatal("empty index")
	}

	// The tunnel path without the Upgrade header gets a plain refusal.
	resp2, err := http.Get(srv.URL + DefaultPath)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("refused upgrade must not switch")
	}
}
