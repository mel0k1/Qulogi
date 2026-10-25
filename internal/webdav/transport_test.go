package webdav

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mel0k1/qulogi/internal/tunnel"
)

// TestStorageTransportEndToEnd drives the whole storage-webdav path:
// tunnel.Client → mailbox pipe → fake cloud → relay → echo target.
func TestStorageTransportEndToEnd(t *testing.T) {
	c := davTestServer(t)

	// The "internet" target: an echo server.
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
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						if _, werr := conn.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()

	// The relay watches the mailbox and serves sessions.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = ServeRelay(ctx, RelayConfig{
			Client:  c,
			Mailbox: "relay-mailbox",
			PSK:     []byte("owl-secret"),
			Poll:    25 * time.Millisecond,
			Log:     func(msg string) { t.Log(msg) },
		})
	}()

	// The client dials through the storage transport.
	dialer := &tunnel.Client{
		PSK: []byte("owl-secret"),
		Conn: func() (net.Conn, error) {
			return OpenPipe(PipeConfig{
				Client: c, Mailbox: "relay-mailbox", Role: RoleClient,
				Chunk: 16 << 10, Poll: 25 * time.Millisecond, Idle: -1,
				Log: func(msg string) { t.Log(msg) },
			})
		},
	}

	var session net.Conn
	t.Run("dial", func(t *testing.T) {
		conn, err := dialer.Dial(tunnel.Address{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port)})
		if err != nil {
			t.Fatal(err)
		}
		session = conn
	})
	defer session.Close()

	// Wrong PSK must be rejected by the relay.
	t.Run("bad psk", func(t *testing.T) {
		bad := &tunnel.Client{
			PSK: []byte("wrong"),
			Conn: func() (net.Conn, error) {
				return OpenPipe(PipeConfig{
					Client: c, Mailbox: "relay-mailbox", Role: RoleClient,
					Chunk: 16 << 10, Poll: 25 * time.Millisecond, Idle: -1,
				})
			},
		}
		conn, err := bad.Dial(tunnel.Address{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port)})
		if err != nil {
			return // handshake error is a valid outcome
		}
		conn.Close()
	})

	if err := session.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello over webdav storage transport")
	for i := 0; i < 3; i++ {
		if _, err := session.Write(msg); err != nil {
			t.Fatalf("write round %d: %v", i, err)
		}
		buf := make([]byte, len(msg))
		if _, err := readFull(session, buf); err != nil {
			t.Fatalf("read round %d: %v", i, err)
		}
		if string(buf) != string(msg) {
			t.Fatalf("round %d: got %q", i, buf)
		}
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
