package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4
	// atypUDP marks a UDP session (0.4.0+): the high bit of the address
	// type switches the payload from a raw TCP stream to framed datagrams.
	// Older relays reject such sessions cleanly via the default branch.
	atypUDPFlag = 0x80
)

type Address struct {
	Host string
	Port uint16
}

func (a Address) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}

func ParseAddress(addr string) (Address, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return Address{}, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return Address{}, fmt.Errorf("tunnel: bad port in %q", addr)
	}
	return Address{Host: host, Port: uint16(port)}, nil
}

func WriteAddress(w io.Writer, a Address) error {
	return WriteAddressMode(w, a, false)
}

// WriteAddressMode writes the address header, marking the session as UDP
// when asked. The flag lives in the high bit of the address type byte, so
// v1 peers parse (and reject) UDP headers without any corruption.
func WriteAddressMode(w io.Writer, a Address, udp bool) error {
	flag := byte(0)
	if udp {
		flag = atypUDPFlag
	}
	head := make([]byte, 0, 262)
	switch ip := net.ParseIP(a.Host); {
	case ip != nil && ip.To4() != nil:
		head = append(head, flag|atypIPv4)
		head = append(head, ip.To4()...)
	case ip != nil:
		head = append(head, flag|atypIPv6)
		head = append(head, ip.To16()...)
	default:
		if len(a.Host) > 255 || len(a.Host) == 0 {
			return errors.New("tunnel: bad host length")
		}
		head = append(head, flag|atypDomain, byte(len(a.Host)))
		head = append(head, a.Host...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], a.Port)
	head = append(head, port[:]...)
	_, err := w.Write(head)
	return err
}

func ReadAddress(r io.Reader) (Address, error) {
	a, _, err := ReadAddressMode(r)
	return a, err
}

// ReadAddressMode parses the address header and reports whether the
// session carries UDP datagrams instead of a raw TCP stream.
func ReadAddressMode(r io.Reader) (Address, bool, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return Address{}, false, err
	}
	udp := atyp[0]&atypUDPFlag != 0
	kind := atyp[0] &^ atypUDPFlag
	var host string
	switch kind {
	case atypIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return Address{}, false, err
		}
		host = net.IP(raw[:]).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return Address{}, false, err
		}
		raw := make([]byte, l[0])
		if _, err := io.ReadFull(r, raw); err != nil {
			return Address{}, false, err
		}
		host = string(raw)
	case atypIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return Address{}, false, err
		}
		host = net.IP(raw[:]).String()
	default:
		return Address{}, false, errors.New("tunnel: bad address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return Address{}, false, err
	}
	return Address{Host: host, Port: binary.BigEndian.Uint16(port[:])}, udp, nil
}
