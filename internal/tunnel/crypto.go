package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const (
	saltSize  = 32
	keySize   = 32
	nonceSize = 12
	tagSize   = 16
	maxFrame  = 65535
	maxInner  = maxFrame - tagSize
)

const (
	infoC2S = "qulogi/v1/c2s"
	infoS2C = "qulogi/v1/s2c"
)

var errAuthFailed = errors.New("tunnel: auth failed")

func hkdf(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(ikm)
	prk := extractor.Sum(nil)

	out := make([]byte, 0, length+sha256.Size)
	var prev []byte
	for i := byte(1); len(out) < length; i++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{i})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

func derive(psk, salt []byte, info string) []byte {
	return hkdf(psk, salt, []byte(info), keySize)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type stream struct {
	net.Conn
	tx    cipher.AEAD
	rx    cipher.AEAD
	txSeq uint64
	rxSeq uint64
	rbuf  []byte
}

func clientHandshake(conn net.Conn, psk []byte) (*stream, error) {
	cSalt := make([]byte, saltSize)
	if _, err := rand.Read(cSalt); err != nil {
		return nil, err
	}
	if _, err := conn.Write(cSalt); err != nil {
		return nil, err
	}
	sSalt := make([]byte, saltSize)
	if _, err := io.ReadFull(conn, sSalt); err != nil {
		return nil, err
	}
	tx, err := newAEAD(derive(psk, cSalt, infoC2S))
	if err != nil {
		return nil, err
	}
	rx, err := newAEAD(derive(psk, sSalt, infoS2C))
	if err != nil {
		return nil, err
	}
	return &stream{Conn: conn, tx: tx, rx: rx}, nil
}

func serverHandshake(conn net.Conn, psk []byte) (*stream, error) {
	cSalt := make([]byte, saltSize)
	if _, err := io.ReadFull(conn, cSalt); err != nil {
		return nil, err
	}
	sSalt := make([]byte, saltSize)
	if _, err := rand.Read(sSalt); err != nil {
		return nil, err
	}
	if _, err := conn.Write(sSalt); err != nil {
		return nil, err
	}
	tx, err := newAEAD(derive(psk, sSalt, infoS2C))
	if err != nil {
		return nil, err
	}
	rx, err := newAEAD(derive(psk, cSalt, infoC2S))
	if err != nil {
		return nil, err
	}
	return &stream{Conn: conn, tx: tx, rx: rx}, nil
}

func (s *stream) Read(p []byte) (int, error) {
	if len(s.rbuf) > 0 {
		n := copy(p, s.rbuf)
		s.rbuf = s.rbuf[n:]
		return n, nil
	}
	var hdr [2]byte
	if _, err := io.ReadFull(s.Conn, hdr[:]); err != nil {
		return 0, err
	}
	size := int(binary.BigEndian.Uint16(hdr[:]))
	if size == 0 || size > maxFrame {
		return 0, errors.New("tunnel: bad frame")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(s.Conn, body); err != nil {
		return 0, err
	}
	var nonce [nonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], s.rxSeq)
	var aad [8]byte
	binary.BigEndian.PutUint64(aad[:], s.rxSeq)
	plain, err := s.rx.Open(nil, nonce[:], body, aad[:])
	if err != nil {
		return 0, errAuthFailed
	}
	s.rxSeq++
	n := copy(p, plain)
	if n < len(plain) {
		s.rbuf = append(s.rbuf[:0], plain[n:]...)
	}
	return n, nil
}

func (s *stream) Write(p []byte) (int, error) {
	sent := 0
	for sent < len(p) {
		end := sent + maxInner
		if end > len(p) {
			end = len(p)
		}
		chunk := p[sent:end]
		var nonce [nonceSize]byte
		binary.BigEndian.PutUint64(nonce[4:], s.txSeq)
		var aad [8]byte
		binary.BigEndian.PutUint64(aad[:], s.txSeq)
		body := s.tx.Seal(nil, nonce[:], chunk, aad[:])
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(body)))
		buf := make([]byte, 0, len(hdr)+len(body))
		buf = append(buf, hdr[:]...)
		buf = append(buf, body...)
		if _, err := s.Conn.Write(buf); err != nil {
			return sent, err
		}
		s.txSeq++
		sent = end
	}
	return sent, nil
}
