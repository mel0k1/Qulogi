package socks5

import (
	"context"
	"io"
	"net"
	"testing"
)

func TestConnectFlow(t *testing.T) {
	up, upSide := net.Pipe()
	defer upSide.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := &Server{
		Listener: ln,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != "example.com:80" {
				t.Errorf("target = %s, want example.com:80", addr)
			}
			return up, nil
		},
	}
	go srv.Serve()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(client, method[:]); err != nil {
		t.Fatal(err)
	}
	if method[0] != 5 || method[1] != 0 {
		t.Fatalf("method reply = %v", method)
	}

	req := []byte{5, 1, 0, 3, 11}
	req = append(req, "example.com"...)
	req = append(req, 0, 80)
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	var rep [10]byte
	if _, err := io.ReadFull(client, rep[:]); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("connect reply code = %d", rep[1])
	}

	go func() {
		client.Write([]byte("PING"))
	}()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(upSide, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "PING" {
		t.Fatalf("upstream got %s", buf)
	}

	go func() {
		upSide.Write([]byte("PONG"))
	}()
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "PONG" {
		t.Fatalf("client got %s", buf)
	}
}
