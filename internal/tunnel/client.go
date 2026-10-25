package tunnel

import (
	"net"
	"time"

	"github.com/mel0k1/qulogi/internal/transport"
)

// Client dials the tunnel server. When Camo is set the connection is
// framed as a TLS session (see internal/transport) before the encrypted
// handshake starts, so DPI observers see ordinary HTTPS to the
// whitelisted SNI instead of an unknown protocol.
type Client struct {
	Server  string
	PSK     []byte
	Timeout time.Duration
	Camo    *transport.ClientOpts
}

func (c *Client) Dial(target Address) (net.Conn, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	conn, err := net.DialTimeout("tcp", c.Server, timeout)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if c.Camo != nil {
		cc, cerr := transport.NewCamoClient(conn, *c.Camo)
		if cerr != nil {
			conn.Close()
			return nil, cerr
		}
		conn = cc
	}
	s, err := clientHandshake(conn, c.PSK)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := WriteAddress(s, target); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
