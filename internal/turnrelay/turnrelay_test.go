package turnrelay

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

func TestMessageRoundTrip(t *testing.T) {
	m := NewMessage(methodAllocate, classRequest)
	m.Add(attrUsername, []byte("owl"))
	m.Add(attrRealm, []byte("qulogi"))
	m.Add(attrNonce, []byte("deadbeef"))
	m.Add(attrReqTransport, []byte{protoUDP, 0, 0, 0})
	key := LongTermKey("owl", "qulogi", "secret")

	raw := m.Encode(key, true)
	got, err := DecodeMessage(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Method != methodAllocate || got.Class != classRequest {
		t.Fatalf("method/class: %d/%d", got.Method, got.Class)
	}
	if !bytes.Equal(got.Get(attrUsername), []byte("owl")) {
		t.Fatalf("username: %q", got.Get(attrUsername))
	}
	if !VerifyMessageIntegrity(raw, key) {
		t.Fatal("integrity must verify")
	}
	wrong := LongTermKey("owl", "qulogi", "wrong")
	if VerifyMessageIntegrity(raw, wrong) {
		t.Fatal("integrity must reject a wrong key")
	}
}

func TestXORAddressRoundTrip(t *testing.T) {
	m := NewMessage(methodConnect, classRequest)
	for _, addr := range []string{"10.1.2.3:5060", "192.168.100.7:443"} {
		v, err := m.encodeXORAddr(addr)
		if err != nil {
			t.Fatalf("encode %s: %v", addr, err)
		}
		back, err := m.PeerAddress(v)
		if err != nil {
			t.Fatalf("decode %s: %v", addr, err)
		}
		if back != addr {
			t.Fatalf("roundtrip: %s -> %s", addr, back)
		}
	}
}

func startTurnServer(t *testing.T, user, realm, pass string) (string, *Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &Server{
		Listener: ln,
		User:     user,
		Realm:    realm,
		Pass:     pass,
		Lifetime: 60 * time.Second,
		Log: func(msg string) {
			t.Logf("%s", msg)
		},
	}
	go srv.Serve()
	t.Cleanup(func() {
		srv.Close()
		srv.Wait()
	})
	return ln.Addr().String(), srv
}

func TestProbeAnonymous(t *testing.T) {
	addr, _ := startTurnServer(t, "", "", "")
	rtt, err := Probe(context.Background(), addr, "", "")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("rtt: %v", rtt)
	}
}

func TestProbeWithCredentials(t *testing.T) {
	addr, _ := startTurnServer(t, "owl", "qulogi", "secret")

	if _, err := Probe(context.Background(), addr, "", ""); err == nil {
		t.Fatal("anonymous probe must fail against a credentialed server")
	}
	if _, err := Probe(context.Background(), addr, "owl", "wrong"); err == nil {
		t.Fatal("wrong password must fail")
	}
	rtt, err := Probe(context.Background(), addr, "owl", "secret")
	if err != nil {
		t.Fatalf("probe with creds: %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("rtt: %v", rtt)
	}
}

func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestDialThroughTurn(t *testing.T) {
	addr, _ := startTurnServer(t, "", "", "")
	echo := startEcho(t)

	cl := &Client{Server: addr, Log: func(msg string) { t.Log(msg) }}
	conn, err := cl.Dial(echo)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := make([]byte, 256*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = conn.Write(payload)
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo mismatch")
	}
	// The stream keeps working after the first round trip.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("second write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("second read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("second echo: %q", buf)
	}
}

func TestDialThroughTurnWithCredentials(t *testing.T) {
	addr, _ := startTurnServer(t, "owl", "qulogi", "secret")
	echo := startEcho(t)

	cl := &Client{Server: addr, User: "owl", Pass: "secret", Fingerprint: true,
		Log: func(msg string) { t.Log(msg) }}
	conn, err := cl.Dial(echo)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo: %q", buf)
	}
}

func TestDialUnreachablePeer(t *testing.T) {
	addr, _ := startTurnServer(t, "", "", "")
	cl := &Client{Server: addr, Timeout: 2 * time.Second}
	// Nothing listens on this port.
	if _, err := cl.Dial("127.0.0.1:1"); err == nil {
		t.Fatal("dial to a dead peer must fail")
	}
}

func TestParseServer(t *testing.T) {
	if got, _ := ParseServer("relay.example.org"); got != "relay.example.org:3478" {
		t.Fatalf("default port: %q", got)
	}
	if got, _ := ParseServer("relay.example.org:443"); got != "relay.example.org:443" {
		t.Fatalf("explicit port: %q", got)
	}
	if _, err := ParseServer(""); err == nil {
		t.Fatal("empty address must fail")
	}
}
