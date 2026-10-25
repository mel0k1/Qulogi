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
	// Conn, when set, supplies an already-established transport for every
	// Dial (storage transports such as WebDAV mailboxes). Camo is ignored
	// for these connections: they are already TLS to the cloud endpoint.
	Conn func() (net.Conn, error)
}

func (c *Client) Dial(target Address) (net.Conn, error) {
	var conn net.Conn
	if c.Conn != nil {
		nc, err := c.Conn()
		if err != nil {
			return nil, err
		}
		conn = nc
	} else {
		timeout := c.Timeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		nc, err := net.DialTimeout("tcp", c.Server, timeout)
		if err != nil {
			return nil, err
		}
		if tc, ok := nc.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		conn = nc
		if c.Camo != nil {
			cc, cerr := transport.NewCamoClient(conn, *c.Camo)
			if cerr != nil {
				conn.Close()
				return nil, cerr
			}
			conn = cc
		}
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
