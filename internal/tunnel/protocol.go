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
	head := make([]byte, 0, 262)
	switch ip := net.ParseIP(a.Host); {
	case ip != nil && ip.To4() != nil:
		head = append(head, atypIPv4)
		head = append(head, ip.To4()...)
	case ip != nil:
		head = append(head, atypIPv6)
		head = append(head, ip.To16()...)
	default:
		if len(a.Host) > 255 || len(a.Host) == 0 {
			return errors.New("tunnel: bad host length")
		}
		head = append(head, atypDomain, byte(len(a.Host)))
		head = append(head, a.Host...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], a.Port)
	head = append(head, port[:]...)
	_, err := w.Write(head)
	return err
}

func ReadAddress(r io.Reader) (Address, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return Address{}, err
	}
	var host string
	switch atyp[0] {
	case atypIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return Address{}, err
		}
		host = net.IP(raw[:]).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return Address{}, err
		}
		raw := make([]byte, l[0])
		if _, err := io.ReadFull(r, raw); err != nil {
			return Address{}, err
		}
		host = string(raw)
	case atypIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return Address{}, err
		}
		host = net.IP(raw[:]).String()
	default:
		return Address{}, errors.New("tunnel: bad address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return Address{}, err
	}
	return Address{Host: host, Port: binary.BigEndian.Uint16(port[:])}, nil
}
