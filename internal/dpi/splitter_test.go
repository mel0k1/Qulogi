package dpi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func u16(v int) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(v))
	return b
}

func buildClientHello(name string) []byte {
	sniBody := append(u16(3+len(name)), 0)
	sniBody = append(sniBody, u16(len(name))...)
	sniBody = append(sniBody, name...)

	sniExt := append([]byte{0x00, 0x00}, u16(len(sniBody))...)
	sniExt = append(sniExt, sniBody...)

	dummy := []byte{0x00, 0x0A, 0x00, 0x00}
	exts := append(append([]byte{}, sniExt...), dummy...)

	hs := []byte{1, 0, 0, 0}
	hs = append(hs, make([]byte, 32)...)
	hs = append(hs, 0x00)
	hs = append(hs, u16(2)...)
	hs = append(hs, 0x13, 0x01)
	hs = append(hs, 0x01, 0x00)
	hs = append(hs, u16(len(exts))...)
	hs = append(hs, exts...)
	binary.BigEndian.PutUint32(hs[1:5], uint32(len(hs)-4))

	rec := []byte{0x16, 0x03, 0x01}
	rec = append(rec, u16(len(hs))...)
	rec = append(rec, hs...)
	return rec
}

func TestClientHelloSplit(t *testing.T) {
	hello := buildClientHello("example.org")
	want := len(hello) - 4

	got := clientHelloSplit(hello)
	if got != want {
		t.Fatalf("split pos = %d, want %d", got, want)
	}

	parts := fragments(hello, 0)
	if len(parts) != 2 || len(parts[0]) != want {
		t.Fatalf("parts = %d, first len = %d", len(parts), len(parts[0]))
	}
	joined := append(append([]byte{}, parts[0]...), parts[1]...)
	if !bytes.Equal(joined, hello) {
		t.Fatal("fragments do not reassemble")
	}
}

func TestFragmentsFallback(t *testing.T) {
	data := []byte("GET / HTTP/1.1")
	if parts := fragments(data, 0); len(parts) != 1 {
		t.Fatal("non-tls data must stay intact")
	}
	if parts := fragments(data, 1); len(parts) != 2 || len(parts[0]) != 1 {
		t.Fatal("manual split failed")
	}

	truncated := buildClientHello("example.org")[:30]
	if p := clientHelloSplit(truncated); p != -1 {
		t.Fatalf("truncated hello split = %d", p)
	}
}
