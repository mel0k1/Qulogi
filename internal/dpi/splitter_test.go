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

func reassemble(parts [][]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestClientHelloSplit(t *testing.T) {
	hello := buildClientHello("example.org")
	want := len(hello) - 4

	if got := clientHelloSplit(hello); got != want {
		t.Fatalf("split pos = %d, want %d", got, want)
	}

	parts := fragments(hello, Default)
	if len(parts) != 2 || len(parts[0]) != want {
		t.Fatalf("parts = %d, first len = %d", len(parts), len(parts[0]))
	}
	if !bytes.Equal(reassemble(parts), hello) {
		t.Fatal("fragments do not reassemble")
	}
}

func TestFragmentsStrategies(t *testing.T) {
	data := []byte("GET / HTTP/1.1")

	if parts := fragments(data, Default); len(parts) != 1 {
		t.Fatal("non-tls data with auto split must stay as one segment")
	}
	parts := fragments(data, Strategy{Split: 1})
	if len(parts) != 2 || len(parts[0]) != 1 {
		t.Fatal("manual split failed")
	}
	if parts := fragments(data, None); len(parts) != 1 || parts[0][0] != 'G' {
		t.Fatal("None must not split")
	}
	if !bytes.Equal(reassemble(fragments(data, Strategy{Split: 5, Multi: true})), data) {
		t.Fatal("multi split must reassemble")
	}

	hello := buildClientHello("example.org")
	parts = fragments(hello, Default)
	if len(parts) != 2 {
		t.Fatal("auto split of hello failed")
	}
	if !bytes.Equal(reassemble(fragments(hello, Strategy{Split: 0, Multi: true})), hello) {
		t.Fatal("multi split of hello must reassemble")
	}
	if p := clientHelloSplit(hello[:30]); p != -1 {
		t.Fatalf("truncated hello split = %d", p)
	}
}

func TestFragmentsMultiThreeSegments(t *testing.T) {
	hello := buildClientHello("example.org")
	parts := fragments(hello, Strategy{Split: 0, Multi: true})
	if len(parts) != 3 {
		t.Fatalf("multi split: got %d segments, want 3", len(parts))
	}
	for i, p := range parts {
		if len(p) == 0 {
			t.Fatalf("segment %d is empty", i)
		}
	}
}
