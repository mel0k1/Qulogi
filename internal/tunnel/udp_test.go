package tunnel

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// udpEcho answers every datagram with the same payload.
func udpEcho(t *testing.T) *net.UDPAddr {
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

func TestTunnelUDPRoundTrip(t *testing.T) {
	echoAddr := udpEcho(t)

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
			go AcceptSession(conn, []byte("owl-udp"), nil)
		}
	}()

	c := &Client{Server: ln.Addr().String(), PSK: []byte("owl-udp")}
	up, err := c.DialUDP(Address{Host: "127.0.0.1", Port: uint16(echoAddr.Port)})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()

	if err := up.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Datagrams preserve boundaries; the 65507-byte maximum rides one frame.
	sizes := []int{1, 100, 1200, 4096, 65507}
	for _, size := range sizes {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i ^ size)
		}
		if _, err := up.Write(payload); err != nil {
			t.Fatalf("write %d: %v", size, err)
		}
		got := make([]byte, size)
		if _, err := readFullConn(up, got); err != nil {
			t.Fatalf("read %d: %v", size, err)
		}
		for i := range payload {
			if got[i] != payload[i] {
				t.Fatalf("size %d: byte %d mismatch", size, i)
			}
		}
	}
}

func TestTunnelUDPAndTCPMix(t *testing.T) {
	// One pipe pair per session: TCP and UDP sessions must not interfere.
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
			go AcceptSession(conn, []byte("owl-mix"), nil)
		}
	}()

	c := &Client{Server: ln.Addr().String(), PSK: []byte("owl-mix")}

	// A TCP session first.
	tcpConn, err := c.Dial(Address{Host: "127.0.0.1", Port: 1})
	if err != nil {
		t.Fatal(err)
	}
	tcpConn.Close()

	// Then UDP sessions.
	for i := 0; i < 3; i++ {
		up, err := c.DialUDP(Address{Host: "127.0.0.1", Port: uint16(5000 + i)})
		if err != nil {
			t.Fatalf("dial udp %d: %v", i, err)
		}
		msg := []byte("ping")
		if _, err := up.Write(msg); err != nil {
			t.Fatal(err)
		}
		up.Close()
	}
}

func TestReadAddressModeFlags(t *testing.T) {
	target := Address{Host: "example.org", Port: 53}

	// The udp flag survives the round trip.
	var udpBuf bytes.Buffer
	if err := WriteAddressMode(&udpBuf, target, true); err != nil {
		t.Fatal(err)
	}
	got, udp, err := ReadAddressMode(&udpBuf)
	if err != nil || !udp || got.Host != target.Host || got.Port != target.Port {
		t.Fatalf("got %+v udp=%v err=%v", got, udp, err)
	}

	// Plain headers stay TCP.
	var tcpBuf bytes.Buffer
	if err := WriteAddressMode(&tcpBuf, target, false); err != nil {
		t.Fatal(err)
	}
	got, udp, err = ReadAddressMode(&tcpBuf)
	if err != nil || udp || got.Host != target.Host {
		t.Fatalf("got %+v udp=%v err=%v", got, udp, err)
	}

	// A v1 parser (no flag knowledge) still reads the plain header.
	var v1Buf bytes.Buffer
	if err := WriteAddress(&v1Buf, target); err != nil {
		t.Fatal(err)
	}
	got, err = ReadAddress(&v1Buf)
	if err != nil || got.Host != target.Host {
		t.Fatalf("v1 parse: %+v %v", got, err)
	}
}

func readFullConn(c net.Conn, buf []byte) (int, error) {
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
