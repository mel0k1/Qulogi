package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func extractSNI(ch []byte) string {
	// record header(5) | hs type(1) + len(3) | version(2) | random(32) | sidlen(1)+sid | cs(2) | comp(1)+comp | extlen(2)
	if len(ch) < 44 {
		return ""
	}
	p := 43
	sidLen := int(ch[p])
	p += 1 + sidLen
	csLen := int(binary.BigEndian.Uint16(ch[p:]))
	p += 2 + csLen
	compLen := int(ch[p])
	p += 1 + compLen
	extTotal := int(binary.BigEndian.Uint16(ch[p:]))
	p += 2
	end := min(p+extTotal, len(ch))
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(ch[p:])
		ln := int(binary.BigEndian.Uint16(ch[p+2:]))
		body := p + 4
		if typ == extServerName && ln >= 5 {
			nameLen := int(binary.BigEndian.Uint16(ch[body+3:]))
			return string(ch[body+5 : body+5+nameLen])
		}
		p = body + ln
	}
	return ""
}

func TestBuildClientHelloShape(t *testing.T) {
	ch := BuildClientHello("rutube.ru")
	if ch[0] != recHandshake || ch[1] != 0x03 || ch[2] != 0x01 {
		t.Fatalf("bad record header: % x", ch[:3])
	}
	recLen := int(binary.BigEndian.Uint16(ch[3:5]))
	if 5+recLen != len(ch) {
		t.Fatalf("record length mismatch: %d vs %d", recLen, len(ch)-5)
	}
	if got := extractSNI(ch); got != "rutube.ru" {
		t.Fatalf("SNI = %q, want rutube.ru", got)
	}
	if len(ch) < 400 || len(ch) > 600 {
		t.Fatalf("suspicious ClientHello size: %d", len(ch))
	}
}

func TestClientHelloRandomized(t *testing.T) {
	a := BuildClientHello("vkvideo.ru")
	b := BuildClientHello("vkvideo.ru")
	if bytes.Equal(a, b) {
		t.Fatal("two ClientHellos are identical, expected randomization")
	}
}

func pipePair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

func TestCamoRoundtrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		wrapped, camo, err := WrapServer(conn)
		if err != nil {
			done <- err
			return
		}
		if !camo {
			done <- errors.New("expected camo detection")
			return
		}
		buf := make([]byte, len("hello qulogi"))
		if err := readFull(wrapped, buf, 2*time.Second); err != nil {
			done <- err
			return
		}
		if string(buf) != "hello qulogi" {
			done <- errors.New("payload mismatch")
			return
		}
		// Answer so the client flight is complete and nothing deadlocks.
		if _, err := wrapped.Write([]byte("pong")); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cc, err := NewCamoClient(conn, ClientOpts{SNI: "vkvideo.ru", FakeCH: true, Split: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cc.Write([]byte("hello qulogi")); err != nil {
		t.Fatal(err)
	}
	pong := make([]byte, 4)
	cc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(cc, pong); err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if string(pong) != "pong" {
		t.Fatalf("pong mismatch: %q", pong)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCamoLargeTransfer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		wrapped, camo, err := WrapServer(conn)
		if err != nil {
			errCh <- err
			return
		}
		if !camo {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		// Echo server.
		buf := make([]byte, 4096)
		for {
			n, err := wrapped.Read(buf)
			if n > 0 {
				if _, werr := wrapped.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		errCh <- nil
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cc, err := NewCamoClient(conn, ClientOpts{SNI: "vkvideo.ru", FakeCH: true, Split: true})
	if err != nil {
		t.Fatal(err)
	}

	big := bytes.Repeat([]byte("qulogi-payload-"), 8000) // 120 KB, spans many records
	go func() {
		if _, err := cc.Write(big); err != nil {
			t.Errorf("write: %v", err)
		}
	}()

	got := make([]byte, len(big))
	cc.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(cc, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, big) {
		t.Fatal("echo mismatch")
	}
}

func TestWrapServerLegacyPassthrough(t *testing.T) {
	cli, srv := pipePair(t)
	go func() {
		_, _ = cli.Write([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	}()
	wrapped, camo, err := WrapServer(srv)
	if err != nil {
		t.Fatal(err)
	}
	if camo {
		t.Fatal("legacy stream misdetected as TLS")
	}
	buf := make([]byte, 8)
	if err := readFull(wrapped, buf, time.Second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("pushback corrupted stream: % x", buf)
	}
}

func readFull(c net.Conn, buf []byte, d time.Duration) error {
	c.SetReadDeadline(time.Now().Add(d))
	_, err := io.ReadFull(c, buf)
	return err
}
