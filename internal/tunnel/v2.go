package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// UDP over the tunnel (0.4.0+): a session whose address header carries the
// udp flag (high bit of the address type) transports framed datagrams:
//
//	[addr with udp flag][2-byte length][datagram][2-byte length][datagram]…
//
// Both directions use the same framing inside the encrypted stream. TCP
// sessions stay byte-identical to v1, so v0.3 relays keep working with
// every new client; a v0.3 relay rejects UDP sessions cleanly (unknown
// address type) instead of corrupting them.
//
// maxInner (65519) comfortably fits the 65507-byte UDP maximum.

const udpIdleTimeout = 90 * time.Second // quiet UDP sessions are reaped

// writeFrame appends one [2-byte length][payload] datagram frame to the
// encrypted stream.
func (s *stream) writeFrame(p []byte) error {
	if len(p) > maxInner {
		return fmt.Errorf("tunnel: datagram %d exceeds %d", len(p), maxInner)
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
	if _, err := s.Write(hdr[:]); err != nil {
		return err
	}
	_, err := s.Write(p)
	return err
}

// readFrame returns the next datagram from the stream.
func (s *stream) readFrame() ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(s, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > maxInner {
		return nil, errors.New("tunnel: bad datagram frame")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(s, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// UDPConn carries UDP datagrams inside one tunnel session. It is a
// net.Conn whose Write emits exactly one datagram frame and whose Read
// returns exactly one datagram (truncating like UDP does), so it drops in
// anywhere a connected UDP socket is expected.
type UDPConn struct {
	s *stream
}

func (c *UDPConn) Write(b []byte) (int, error) {
	if len(b) > maxInner {
		return 0, fmt.Errorf("tunnel: datagram %d exceeds %d", len(b), maxInner)
	}
	if err := c.s.writeFrame(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *UDPConn) Read(b []byte) (int, error) {
	dg, err := c.s.readFrame()
	if err != nil {
		return 0, err
	}
	n := copy(b, dg) // UDP semantics: oversized datagrams truncate
	return n, nil
}

func (c *UDPConn) Close() error                       { return c.s.Conn.Close() }
func (c *UDPConn) LocalAddr() net.Addr                { return c.s.Conn.LocalAddr() }
func (c *UDPConn) RemoteAddr() net.Addr               { return c.s.Conn.RemoteAddr() }
func (c *UDPConn) SetDeadline(t time.Time) error      { return c.s.Conn.SetDeadline(t) }
func (c *UDPConn) SetReadDeadline(t time.Time) error  { return c.s.Conn.SetReadDeadline(t) }
func (c *UDPConn) SetWriteDeadline(t time.Time) error { return c.s.Conn.SetWriteDeadline(t) }

// relayUDPSession pipes framed datagrams between the tunnel stream and a
// connected UDP socket. Quiet sessions are reaped after udpIdleTimeout.
func relayUDPSession(sk *stream, target Address, log func(string)) error {
	udp, err := net.DialTimeout("udp", target.String(), 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial udp %s: %w", target.String(), err)
	}
	defer udp.Close()
	if log != nil {
		log("open udp " + target.String())
	}

	done := make(chan error, 2)
	go func() { // tunnel -> network
		for {
			dg, err := sk.readFrame()
			if err != nil {
				done <- err
				return
			}
			if _, err := udp.Write(dg); err != nil {
				done <- err
				return
			}
		}
	}()
	go func() { // network -> tunnel
		buf := make([]byte, 65535)
		for {
			_ = udp.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, err := udp.Read(buf)
			if err != nil {
				done <- err
				return
			}
			if err := sk.writeFrame(buf[:n]); err != nil {
				done <- err
				return
			}
		}
	}()
	err = <-done
	if log != nil {
		log("close udp " + target.String())
	}
	return err
}
