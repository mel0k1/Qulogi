package transport

import (
	"encoding/binary"
	"errors"
)

// ParseClientHello inspects the head of a client TCP stream and extracts
// the ServerName (SNI) from the TLS ClientHello, if one is there. It is
// used by the VPN TUN stack, where flows arrive as raw IP:port pairs and
// the hostname needed for the smart split only becomes visible once the
// client sends its hello.
//
// Returns:
//   - sni        — the server name ("" when the hello has none);
//   - isHello    — true when data is a TLS record that turned out to be a
//     (complete or incomplete) ClientHello;
//   - incomplete — true when more bytes are needed to finish parsing.
//     Callers should keep reading and call again with a longer buffer.
//
// Everything else (plaintext protocols, TLS without a ClientHello, garbage)
// returns isHello=false and is safe to forward as-is.
func ParseClientHello(data []byte) (sni string, isHello bool, incomplete bool) {
	// Nothing buffered: there is nothing to wait for either.
	if len(data) == 0 {
		return "", false, false
	}
	// A lone first byte is not enough to decide anything.
	if len(data) < 5 {
		if data[0] != recHandshake {
			return "", false, false
		}
		return "", true, true
	}
	if data[0] != recHandshake || data[1] != 0x03 {
		return "", false, false
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recLen == 0 {
		return "", true, false
	}
	if 5+recLen > len(data) {
		// Records larger than the sniff window can never finish parsing.
		if recLen > maxSniffRecord {
			return "", true, false
		}
		return "", true, true
	}
	rec := data[5 : 5+recLen]
	if len(rec) < 9 {
		// A complete record that cannot even hold a handshake header is
		// malformed — there is no point in waiting for more bytes.
		return "", true, false
	}
	if rec[0] != 0x01 { // not a ClientHello (alert, other handshake)
		return "", false, false
	}
	hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
	if hsLen > len(rec)-4 {
		return "", true, true
	}
	body := rec[4 : 4+hsLen]

	p := 2 + 32 // legacy version + random
	if p+1 > len(body) {
		return "", true, true
	}
	p += 1 + int(body[p]) // session id
	if p+2 > len(body) {
		return "", true, true
	}
	p += 2 + int(binary.BigEndian.Uint16(body[p:])) // cipher suites
	if p+1 > len(body) {
		return "", true, true
	}
	p += 1 + int(body[p]) // compression methods
	if p+2 > len(body) {
		return "", true, true
	}
	// TLS 1.3 middlebox compat: some clients append a dummy change_cipher_spec
	// record after the hello — irrelevant here, we only parse the first record.
	extTotal := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	extEnd := p + extTotal
	if extEnd > len(body) {
		return "", true, true
	}
	for p+4 <= extEnd {
		typ := binary.BigEndian.Uint16(body[p:])
		ln := int(binary.BigEndian.Uint16(body[p+2:]))
		ext := p + 4
		if ext+ln > extEnd {
			return "", true, true
		}
		if typ == 0 { // server_name
			name, err := parseSNIExt(body[ext : ext+ln])
			if err != nil {
				return "", true, false
			}
			return name, true, false
		}
		p = ext + ln
	}
	return "", true, false
}

// parseSNIExt decodes the server_name extension body: a list with one
// entry of type "host_name" in practice.
func parseSNIExt(b []byte) (string, error) {
	if len(b) < 2 {
		return "", errors.New("transport: short sni extension")
	}
	listLen := int(binary.BigEndian.Uint16(b))
	if 2+listLen > len(b) {
		return "", errors.New("transport: sni list overrun")
	}
	p := 2
	for p+3 <= 2+listLen {
		if b[p] != 0 { // not host_name
			p += 1 + 2 + int(binary.BigEndian.Uint16(b[p+1:p+3]))
			continue
		}
		nl := int(binary.BigEndian.Uint16(b[p+1 : p+3]))
		p += 3
		if p+nl > 2+listLen {
			return "", errors.New("transport: sni name overrun")
		}
		return string(b[p : p+nl]), nil
	}
	return "", nil
}

// maxSniffRecord bounds the record length that sniffing is willing to wait
// for. A ClientHello is at most ~48 KiB by RFC 8446 limits; anything above
// is not worth buffering.
const maxSniffRecord = 60000
