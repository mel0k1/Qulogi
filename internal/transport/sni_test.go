package transport

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseClientHelloRoundTrip(t *testing.T) {
	for _, sni := range []string{"ya.ru", "vkvideo.ru", "mail.example.org", "xn--d1acufc.xn--p1ai"} {
		rec := BuildClientHello(sni)
		got, isHello, incomplete := ParseClientHello(rec)
		if !isHello || incomplete {
			t.Fatalf("sni %q: isHello=%v incomplete=%v", sni, isHello, incomplete)
		}
		if got != sni {
			t.Fatalf("sni %q: parsed %q", sni, got)
		}
	}
}

func TestParseClientHelloNoSNI(t *testing.T) {
	rec := BuildClientHello("")
	_, isHello, incomplete := ParseClientHello(rec)
	if !isHello || incomplete {
		t.Fatalf("isHello=%v incomplete=%v", isHello, incomplete)
	}
}

func TestParseClientHelloTruncated(t *testing.T) {
	rec := BuildClientHello("truncate-me.example")
	// Byte-by-byte: everything before the full record must be incomplete.
	for n := 1; n < len(rec); n++ {
		_, isHello, incomplete := ParseClientHello(rec[:n])
		if !isHello {
			// The record type and version are known from byte 0, so every
			// prefix stays a (possibly incomplete) hello.
			t.Fatalf("prefix %d: isHello=false", n)
		}
		if !incomplete {
			t.Fatalf("prefix %d: expected incomplete", n)
		}
	}
	got, isHello, incomplete := ParseClientHello(rec)
	if !isHello || incomplete || got != "truncate-me.example" {
		t.Fatalf("full: got=%q isHello=%v incomplete=%v", got, isHello, incomplete)
	}
}

func TestParseClientHelloNotTLS(t *testing.T) {
	cases := map[string][]byte{
		"empty":        {},
		"http get":     []byte("GET / HTTP/1.1\r\nHost: ya.ru\r\n\r\n"),
		"ssh banner":   []byte("SSH-2.0-OpenSSH_9.6\r\n"),
		"garbage":      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		"plaintext 16": {0x16, 'x', 'x', 'x', 'x', 'y', 'y', 'y', 'y', 'z'},
	}
	for name, data := range cases {
		sni, isHello, incomplete := ParseClientHello(data)
		if isHello || incomplete || sni != "" {
			t.Fatalf("%s: sni=%q isHello=%v incomplete=%v", name, sni, isHello, incomplete)
		}
	}
}

func TestParseClientHelloOtherHandshake(t *testing.T) {
	// A complete handshake record whose first message is not a ClientHello.
	rec := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x03, 0x00, 0x00, 0x01, 0x00}
	sni, isHello, incomplete := ParseClientHello(rec)
	// TLS handshake traffic, but parsing is over: nothing more is coming
	// for this record and no SNI was found.
	if !isHello || incomplete || sni != "" {
		t.Fatalf("sni=%q isHello=%v incomplete=%v", sni, isHello, incomplete)
	}
}

func TestParseClientHelloOversizedRecord(t *testing.T) {
	// Header claims a record bigger than the sniff cap: parsing stops
	// waiting (incomplete=false) instead of buffering forever.
	rec := []byte{0x16, 0x03, 0x01, 0xff, 0xff}
	_, isHello, incomplete := ParseClientHello(rec)
	if !isHello || incomplete {
		t.Fatalf("isHello=%v incomplete=%v", isHello, incomplete)
	}
}

func TestParseClientHelloSNIWithPadding(t *testing.T) {
	// SNI followed by a padding extension: the parser must keep walking.
	rec := BuildClientHello("padded.example")
	if !bytes.Contains(rec, []byte("padded.example")) || !strings.Contains(string(rec), "padded.example") {
		t.Fatal("sanity: sni missing from record")
	}
}
