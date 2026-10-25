// Package transport adds a TLS-shaped camouflage layer on top of the
// encrypted tunnel stream. On the wire the connection looks like a TLS
// session against a whitelisted service: the client emits a realistic
// ClientHello (with a configurable SNI), the server answers with a
// ServerHello/ChangeCipherSpec flight, and every payload byte afterwards
// travels inside TLS application-data records.
//
// It is pure camouflage: no real TLS handshake happens, authentication and
// encryption stay with the tunnel's AES-256-GCM framing underneath.
package transport

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

const (
	recHeaderSize       = 5
	maxRecordPayload    = 16384
	maxHandshakeDiscard = 32 * 1024 // cap for camouflage records we are willing to swallow
)

// TLS record content types.
const (
	recChangeCipherSpec = 0x14
	recAlert            = 0x15
	recHandshake        = 0x16
	recAppData          = 0x17
)

var errRecordTooLarge = errors.New("transport: record exceeds 16384 bytes")

func appendRecord(dst, payload []byte, ctype byte, version []byte) []byte {
	dst = append(dst, ctype, version[0], version[1])
	var ln [2]byte
	binary.BigEndian.PutUint16(ln[:], uint16(len(payload)))
	dst = append(dst, ln[:]...)
	return append(dst, payload...)
}

func readRecord(r io.Reader) (ctype byte, payload []byte, err error) {
	var hdr [recHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	ctype = hdr[0]
	size := int(binary.BigEndian.Uint16(hdr[3:5]))
	if size > maxRecordPayload {
		return 0, nil, errRecordTooLarge
	}
	payload = make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return ctype, payload, nil
}

// looksLikeTLS reports whether b begins with a TLS handshake record header.
func looksLikeTLS(b []byte) bool {
	return len(b) >= 5 && b[0] == recHandshake && b[1] == 0x03 && b[2] <= 0x04
}

// jitterPause emulates human-ish pacing between the ClientHello record and
// the follow-up traffic so the two never land in the same TCP segment burst.
func jitterPause() {
	d := time.Duration(8+time.Now().UnixNano()%37) * time.Millisecond
	time.Sleep(d)
}
