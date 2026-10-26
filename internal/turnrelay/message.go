// Package turnrelay implements the turn-relay transport class from
// docs/RELAY_DISCOVERY.md: tunnel frames carried through TURN servers
// (RFC 5766) with TCP peer allocations (RFC 6062).
//
//	device ──TCP──► TURN server ──TCP──► qulogi relay
//
// TURN servers exist for WebRTC, so they are reachable from most networks
// — corporate, mobile and filtered ones. A TURN server reachable from the
// user's network becomes a transport: the client allocates a TCP peer
// connection through it and runs the ordinary qulogi tunnel over that
// stream. The wire only ever carries STUN/TURN plus the opaque tunnel.
//
// The client uses the RFC 6062 flow over a TCP transport to the server:
//
//	Allocate            → relayed address (+ long-term credentials)
//	Connect(peer)       → connection id
//	ConnectionBind(id)  → a raw data connection to the peer
//
// Long-term credentials (RFC 5389 §15.4) are supported:
// key = MD5(user ":" realm ":" pass). Anonymous servers work with empty
// credentials. Probe measures the RTT of a full Allocate — the
// reconnaissance primitive for the catalog pipeline. A minimal RFC 6062
// server (Server) lives here as well: it powers the tests, the smoke
// pipeline and cmd/qulogiturn for community relays.
package turnrelay

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"strconv"
	"time"
)

// STUN magic cookie (RFC 5389 §6).
const magicCookie = 0x2112A442

// STUN methods and classes used by the TURN flow.
const (
	methodAllocate       = 0x003
	methodRefresh        = 0x004
	methodCreatePermissi = 0x008
	methodConnect        = 0x00A
	methodConnectionBind = 0x00B

	classRequest    = 0x0
	classIndication = 0x1
	classSuccess    = 0x2
	classError      = 0x3
)

// STUN/TURN attribute types.
const (
	attrMappedAddress  = 0x0001
	attrUsername       = 0x0006
	attrMessageIntegr  = 0x0008
	attrErrorCode      = 0x0009
	attrLifetime       = 0x000D
	attrXORPeerAddress = 0x0012
	attrRealm          = 0x0014
	attrNonce          = 0x0015
	attrXORRelayedAddr = 0x0016
	attrReqTransport   = 0x0019
	attrDontFragment   = 0x001A
	attrConnectionID   = 0x002A
	attrFingerprint    = 0x8028
)

// protoUDP is the transport protocol number for REQUESTED-TRANSPORT
// (RFC 5766 §5.1): allocations are always UDP, RFC 6062 layers TCP peers
// on top of them.
const protoUDP = 17

const fingerprintXOR = 0x5354554e

// Message is a decoded STUN message.
type Message struct {
	Method      int
	Class       int
	Transaction [12]byte

	attrs map[int][]byte
	order []int
}

// methodClass splits a STUN message type into method and class
// (RFC 5389 §5).
func methodClass(t int) (int, int) {
	m := t>>9&0x1<<11 | t>>6&0x1F<<7 | t&0xF
	c := t>>7&0x2 | t>>4&0x1
	return m, c
}

func typeOf(method, class int) int {
	return method&0xF80<<2 | method&0x070<<1 | method&0x00F |
		class&0x2<<7 | class&0x1<<4
}

// NewMessage builds an empty message with a random transaction id.
func NewMessage(method, class int) *Message {
	m := &Message{Method: method, Class: class, attrs: map[int][]byte{}}
	if _, err := rand.Read(m.Transaction[:]); err != nil {
		panic("turnrelay: entropy unavailable: " + err.Error())
	}
	return m
}

// Add appends an attribute (later values win for Get).
func (m *Message) Add(t int, v []byte) {
	if _, ok := m.attrs[t]; !ok {
		m.order = append(m.order, t)
	}
	m.attrs[t] = v
}

// Get returns the last value of an attribute (nil when absent).
func (m *Message) Get(t int) []byte { return m.attrs[t] }

// Has reports whether the attribute is present.
func (m *Message) Has(t int) bool { _, ok := m.attrs[t]; return ok }

// Encode renders the message. With a key, MESSAGE-INTEGRITY is appended
// (HMAC-SHA1 with the long-term credential key); with fp, FINGERPRINT
// follows (CRC32). Per RFC 5389 the integrity hash covers the message as
// if it ended right after MESSAGE-INTEGRITY; the fingerprint hash covers
// everything including it, with the header length adjusted each time.
func (m *Message) Encode(key []byte, fp bool) []byte {
	body := make([]byte, 0, 96)
	for _, t := range m.order {
		v := m.attrs[t]
		body = binary.BigEndian.AppendUint16(body, uint16(t))
		body = binary.BigEndian.AppendUint16(body, uint16(len(v)))
		body = append(body, v...)
		if pad := len(v) % 4; pad != 0 {
			body = append(body, make([]byte, 4-pad)...)
		}
	}
	// The header length counts the whole message on the wire, security
	// attributes included (the integrity hash adjusts it on its own).
	wireLen := len(body)
	if key != nil {
		wireLen += 24
	}
	if fp {
		wireLen += 8
	}
	head := make([]byte, 20)
	binary.BigEndian.PutUint16(head[0:2], uint16(typeOf(m.Method, m.Class)))
	binary.BigEndian.PutUint16(head[2:4], uint16(wireLen))
	binary.BigEndian.PutUint32(head[4:8], magicCookie)
	copy(head[8:20], m.Transaction[:])

	out := append(head, body...)
	if key != nil {
		mac := stunHMAC(out[:20], out[20:], key, len(body)+24)
		out = append(out, 0x00, byte(attrMessageIntegr), 0x00, 0x14)
		out = append(out, mac...)
	}
	if fp {
		binary.BigEndian.PutUint16(out[2:4], uint16(wireLen))
		crc := crc32.ChecksumIEEE(out) ^ fingerprintXOR
		out = append(out, 0x80, 0x28, 0x00, 0x04)
		out = binary.BigEndian.AppendUint32(out, crc)
	}
	return out
}

// stunHMAC computes STUN MESSAGE-INTEGRITY: HMAC-SHA1 over the 20-byte
// header (with the length adjusted to totalLen) followed by the
// attributes preceding the integrity attribute.
func stunHMAC(head, attrs, key []byte, totalLen int) []byte {
	h := append([]byte(nil), head...)
	binary.BigEndian.PutUint16(h[2:4], uint16(totalLen))
	mac := hmac.New(sha1.New, key)
	mac.Write(h)
	mac.Write(attrs)
	return mac.Sum(nil)
}

// ErrNotStun reports bytes that are not a STUN message.
var ErrNotStun = errors.New("turnrelay: not a stun message")

// DecodeMessage parses a STUN message. The fingerprint is dropped (its
// value depends on the raw bytes, useless after re-encoding); everything
// else is kept.
func DecodeMessage(b []byte) (*Message, error) {
	if len(b) < 20 || b[0]&0xC0 != 0 {
		return nil, ErrNotStun
	}
	mlen := int(binary.BigEndian.Uint16(b[2:4]))
	if binary.BigEndian.Uint32(b[4:8]) != magicCookie {
		return nil, ErrNotStun
	}
	if 20+mlen > len(b) {
		return nil, fmt.Errorf("turnrelay: truncated stun message (%d < %d)", len(b), 20+mlen)
	}
	method, class := methodClass(int(binary.BigEndian.Uint16(b[0:2])))
	m := &Message{Method: method, Class: class, attrs: map[int][]byte{}}
	copy(m.Transaction[:], b[8:20])
	p := b[20 : 20+mlen]
	for len(p) >= 4 {
		t := int(binary.BigEndian.Uint16(p[0:2]))
		l := int(binary.BigEndian.Uint16(p[2:4]))
		if 4+l > len(p) {
			return nil, fmt.Errorf("turnrelay: bad attribute 0x%04x", t)
		}
		if t != attrFingerprint {
			m.Add(t, append([]byte(nil), p[4:4+l]...))
		}
		pad := l % 4
		p = p[4+l+(4-pad)&3:]
	}
	return m, nil
}

// xport decodes the xor'ed port.
func xport(raw []byte) uint16 {
	return binary.BigEndian.Uint16(raw[2:4]) ^ (magicCookie >> 16)
}

// encodeXORAddr builds an XOR-*ADDRESS attribute value for addr using the
// message transaction id as part of the mask.
func (m *Message) encodeXORAddr(addr string) ([]byte, error) {
	host, portS, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("turnrelay: address %q: %w", addr, err)
	}
	port, err := strconv.ParseUint(portS, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("turnrelay: port in %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("turnrelay: bad ip %q", host)
	}
	v4 := ip.To4()
	fam := byte(0x02)
	alen := 16
	if v4 != nil {
		fam, alen = 0x01, 4
		ip = v4
	}
	out := make([]byte, 4+alen)
	out[1] = fam
	binary.BigEndian.PutUint16(out[2:4], uint16(port)^(magicCookie>>16))
	var cookie [4]byte
	binary.BigEndian.PutUint32(cookie[:], magicCookie)
	for i := 0; i < alen; i++ {
		k := cookie[i%4]
		if i >= 12 {
			k ^= m.Transaction[i-12]
		}
		out[4+i] = ip[i] ^ k
	}
	return out, nil
}

// PeerAddress decodes an XOR-PEER/XOR-RELAYED/XOR-MAPPED address value.
func (m *Message) PeerAddress(v []byte) (string, error) {
	if len(v) < 8 {
		return "", errors.New("turnrelay: short xor address")
	}
	switch v[1] {
	case 0x01:
		if len(v) < 8 {
			return "", errors.New("turnrelay: short ipv4 xor address")
		}
		ip := make(net.IP, 4)
		var cookie [4]byte
		binary.BigEndian.PutUint32(cookie[:], magicCookie)
		for i := 0; i < 4; i++ {
			ip[i] = v[4+i] ^ cookie[i]
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(xport(v)))), nil
	case 0x02:
		if len(v) < 20 {
			return "", errors.New("turnrelay: short ipv6 xor address")
		}
		ip := make(net.IP, 16)
		var cookie [4]byte
		binary.BigEndian.PutUint32(cookie[:], magicCookie)
		for i := 0; i < 16; i++ {
			k := cookie[i%4]
			if i >= 12 {
				k ^= m.Transaction[i-12]
			}
			ip[i] = v[4+i] ^ k
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(xport(v)))), nil
	default:
		return "", fmt.Errorf("turnrelay: unknown address family %d", v[1])
	}
}

// errCode extracts the numeric code and reason from an ERROR-CODE value.
func errCode(v []byte) (int, string) {
	if len(v) < 4 {
		return 0, ""
	}
	reason := ""
	if len(v) > 4 {
		reason = string(v[4:])
	}
	return int(v[2]&0x7)*100 + int(v[3]), reason
}

// LongTermKey derives the RFC 5389 long-term credential key:
// MD5(username ":" realm ":" password).
func LongTermKey(user, realm, pass string) []byte {
	h := md5.Sum([]byte(user + ":" + realm + ":" + pass))
	return h[:]
}

// readMessage frames exactly one STUN message off the wire and decodes it.
func readMessage(c net.Conn, deadline time.Time) (*Message, error) {
	msg, _, err := readMessageRaw(c, deadline)
	return msg, err
}

// readMessageRaw frames exactly one STUN message off the wire and returns
// both the decoded message and the raw bytes (needed for
// MESSAGE-INTEGRITY verification).
func readMessageRaw(c net.Conn, deadline time.Time) (*Message, []byte, error) {
	if !deadline.IsZero() {
		_ = c.SetReadDeadline(deadline)
	}
	head := make([]byte, 20)
	if _, err := ioReadFull(c, head); err != nil {
		return nil, nil, err
	}
	mlen := int(binary.BigEndian.Uint16(head[2:4]))
	body := make([]byte, mlen)
	if _, err := ioReadFull(c, body); err != nil {
		return nil, nil, err
	}
	raw := append(head, body...)
	msg, err := DecodeMessage(raw)
	if err != nil {
		return nil, nil, err
	}
	return msg, raw, nil
}

// VerifyMessageIntegrity checks the MESSAGE-INTEGRITY attribute of a raw
// message against the long-term credential key. It reports false when the
// attribute is absent, malformed or the HMAC does not match.
func VerifyMessageIntegrity(raw []byte, key []byte) bool {
	if key == nil || len(raw) < 20+24 {
		return false
	}
	mlen := int(binary.BigEndian.Uint16(raw[2:4]))
	if 20+mlen > len(raw) {
		return false
	}
	p := raw[20 : 20+mlen]
	off := 20
	for len(p) >= 4 {
		t := int(binary.BigEndian.Uint16(p[0:2]))
		l := int(binary.BigEndian.Uint16(p[2:4]))
		if t == attrMessageIntegr {
			if l != 20 || off+24 > len(raw) {
				return false
			}
			want := stunHMAC(raw[:20], raw[20:off], key, off+24-20)
			return hmac.Equal(want, raw[off+4:off+24])
		}
		adv := 4 + l + (4-l%4)&3
		p = p[adv:]
		off += adv
	}
	return false
}

// errCodeValue renders an ERROR-CODE attribute value (RFC 5389 §15.6):
// three class bits (the hundreds) followed by the number byte.
func errCodeValue(code int, reason string) []byte {
	v := make([]byte, 4+len(reason))
	v[2] = byte((code / 100) & 0x7)
	v[3] = byte(code % 100)
	copy(v[4:], reason)
	return v
}

func ioReadFull(c net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		nn, err := c.Read(buf[n:])
		if err != nil {
			return n, err
		}
		n += nn
	}
	return n, nil
}
