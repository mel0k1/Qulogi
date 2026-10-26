package cdnfront

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mel0k1/qulogi/internal/tunnel"
)

// wsPipe wires two wsStream ends over net.Pipe (client left, server right).
func wsPipe() (client *wsStream, server *wsStream) {
	a, b := net.Pipe()
	return newWSClientStream(a), newWSServerStream(b)
}

func TestWSStreamRoundtrip(t *testing.T) {
	c, s := wsPipe()
	defer c.Close()
	defer s.Close()

	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	t.Run("sizes", func(t *testing.T) {
		for _, size := range []int{1, 100, 125, 126, 4096, 0xFFFF, 0xFFFF + 1, 300000} {
			msg := make([]byte, size)
			if _, err := rand.Read(msg); err != nil {
				t.Fatal(err)
			}
			errCh := make(chan error, 1)
			go func() { _, err := c.Write(msg); errCh <- err }()
			got := make([]byte, size)
			if _, err := io.ReadFull(s, got); err != nil {
				t.Fatalf("server read %d: %v", size, err)
			}
			if err := <-errCh; err != nil {
				t.Fatalf("client write %d: %v", size, err)
			}
			if !bytes.Equal(got, msg) {
				t.Fatalf("size %d: payload mismatch", size)
			}
			go func() { _, err := s.Write(msg); errCh <- err }()
			if _, err := io.ReadFull(c, got); err != nil {
				t.Fatalf("client read %d: %v", size, err)
			}
			if err := <-errCh; err != nil {
				t.Fatalf("server write %d: %v", size, err)
			}
			if !bytes.Equal(got, msg) {
				t.Fatalf("size %d: round-trip mismatch", size)
			}
		}
	})

	t.Run("ping answered with pong", func(t *testing.T) {
		go func() {
			_ = s.writeControl(0x9, []byte("hb"))
			_, _ = s.Write([]byte("after-ping"))
		}()
		msg := []byte("after-ping")
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("read after ping: %v", err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("payload: %q", got)
		}
		payload, opcode, err := s.readFrame()
		if err != nil {
			t.Fatalf("pong read: %v", err)
		}
		if opcode != 0xA || string(payload) != "hb" {
			t.Fatalf("expected pong(hb), got opcode 0x%x %q", opcode, payload)
		}
	})

	t.Run("close is EOF", func(t *testing.T) {
		sc, ss := wsPipe()
		defer sc.Close()
		defer ss.Close()
		if err := sc.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		errCh := make(chan error, 1)
		go func() { // park the reader before the close frame is written
			buf := make([]byte, 8)
			_, err := sc.Read(buf)
			errCh <- err
		}()
		time.Sleep(50 * time.Millisecond)
		if err := ss.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-errCh; err != io.EOF {
			t.Fatalf("expected EOF after close, got %v", err)
		}
	})
}

func TestWSFrontEndToEnd(t *testing.T) {
	const psk = "owl-ws-front"

	// The fake CDN edge: TLS termination, Host routing, WS passthrough.
	front := &Server{PSK: []byte(psk)}
	edge := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "relay.example.net" {
			http.Error(w, "unknown host", http.StatusNotFound)
			return
		}
		front.ServeHTTP(w, r)
	}))
	defer edge.Close()

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

	f := &WSFront{
		EdgeAddr:           edge.Listener.Addr().String(),
		EdgeSNI:            "white.cdn.example",
		Host:               "relay.example.net",
		InsecureSkipVerify: true,
	}
	client := &tunnel.Client{PSK: []byte(psk), Conn: f.Dial}
	echoPort := uint16(ln.Addr().(*net.TCPAddr).Port)

	t.Run("tcp stream through ws frames", func(t *testing.T) {
		session, err := client.Dial(tunnel.Address{Host: "127.0.0.1", Port: echoPort})
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		if err := session.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		msg := []byte("hello through the real cdn websocket")
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

	t.Run("udp datagrams through ws frames", func(t *testing.T) {
		udpEcho := udpEchoServer(t)
		up, err := client.DialUDP(tunnel.Address{Host: "127.0.0.1", Port: uint16(udpEcho.Port)})
		if err != nil {
			t.Fatal(err)
		}
		defer up.Close()
		if err := up.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		for _, msg := range [][]byte{[]byte("dg-ws"), make([]byte, 1200)} {
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

// TestWSFrontLegacyCompatibility proves a WS-speaking client still works
// against a pre-0.6 front that only confirms the bare qulogi upgrade.
func TestWSFrontLegacyCompatibility(t *testing.T) {
	legacy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !containsFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "no", http.StatusMisdirectedRequest)
			return
		}
		hj := w.(http.Hijacker)
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		// A pre-0.6 qulogi front accepts any upgrade it does not
		// understand as the bare switch (it only greps for "qulogi").
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: qulogi/1\r\nConnection: Upgrade\r\n\r\n"
		if _, err := conn.Write([]byte(resp)); err != nil {
			return
		}
		io.Copy(conn, conn)
	}))
	defer legacy.Close()

	f := &WSFront{
		EdgeAddr:           legacy.Listener.Addr().String(),
		Host:               "relay.example.net",
		InsecureSkipVerify: true,
	}
	conn, err := f.Dial()
	if err != nil {
		t.Fatalf("legacy front must keep working: %v", err)
	}
	defer conn.Close()
	msg := []byte("raw stream after legacy 101")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: %q", got)
	}
}

// TestSameHostFrontProfile checks the default posture builder.
func TestSameHostFrontProfile(t *testing.T) {
	f := SameHostFront("relay.example.net")
	if f.EdgeAddr != "relay.example.net" || f.EdgeSNI != "relay.example.net" || f.Host != "relay.example.net" {
		t.Fatalf("same-host front: %+v", f)
	}
	p, ok := LookupProfile("CloudFlare")
	if !ok || !p.WebSockets || p.Frontable {
		t.Fatalf("profile lookup: %+v ok=%v", p, ok)
	}
	if _, ok := LookupProfile("no-such"); ok {
		t.Fatal("unknown profile must not resolve")
	}
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
