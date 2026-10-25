package dpi

import (
	"encoding/binary"
	"io"
	"net"
)

const maxFirstRead = 32 * 1024

func Pump(split int) func(client, upstream net.Conn) error {
	return func(client, upstream net.Conn) error {
		if tc, ok := upstream.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}
		errc := make(chan error, 2)
		go func() {
			_, err := io.Copy(client, upstream)
			errc <- err
		}()
		go func() {
			errc <- copySplit(upstream, client, split)
		}()
		err := <-errc
		client.Close()
		upstream.Close()
		<-errc
		return err
	}
}

func copySplit(upstream, client net.Conn, split int) error {
	buf := make([]byte, maxFirstRead)
	n, err := client.Read(buf)
	if n > 0 {
		for _, part := range fragments(buf[:n], split) {
			if _, werr := upstream.Write(part); werr != nil {
				return werr
			}
		}
	}
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	_, err = io.Copy(upstream, client)
	return err
}

func fragments(data []byte, split int) [][]byte {
	pos := 0
	if len(data) > 0 && data[0] == 0x16 {
		if p := clientHelloSplit(data); p > 0 {
			pos = p
		} else if split > 0 {
			pos = min(split, len(data))
		} else {
			pos = 1
		}
	} else if split > 0 {
		pos = min(split, len(data))
	}
	if pos <= 0 || pos >= len(data) {
		return [][]byte{data}
	}
	return [][]byte{data[:pos], data[pos:]}
}

func clientHelloSplit(data []byte) int {
	if len(data) < 48 {
		return -1
	}
	if data[0] != 0x16 || data[1] != 3 {
		return -1
	}
	if data[5] != 1 {
		return -1
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+recLen > len(data) {
		return -1
	}
	end := 5 + recLen
	p := 9 + 32
	if p+1 > end {
		return -1
	}
	sidLen := int(data[p])
	p += 1 + sidLen
	if p+2 > end {
		return -1
	}
	csLen := int(binary.BigEndian.Uint16(data[p:]))
	p += 2 + csLen
	if p+1 > end {
		return -1
	}
	compLen := int(data[p])
	p += 1 + compLen
	if p+2 > end {
		return -1
	}
	extTotal := int(binary.BigEndian.Uint16(data[p:]))
	p += 2
	extEnd := min(p+extTotal, end)
	for p+4 <= extEnd {
		typ := binary.BigEndian.Uint16(data[p:])
		ln := int(binary.BigEndian.Uint16(data[p+2:]))
		body := p + 4
		if body+ln > extEnd {
			return -1
		}
		if typ == 0 && ln >= 5 {
			nameLen := int(binary.BigEndian.Uint16(data[body+3:]))
			pos := body + 5 + nameLen
			if pos > 0 && pos < len(data) {
				return pos
			}
			return -1
		}
		p = body + ln
	}
	return -1
}
