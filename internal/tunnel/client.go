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
	sk, err := c.handshake(target, false)
	if err != nil {
		return nil, err
	}
	return sk, nil
}

// DialUDP opens a UDP tunnel session to target: framed datagrams in both
// directions inside one encrypted session. The returned net.Conn preserves
// datagram boundaries (one Write = one datagram, one Read = one datagram,
// oversized datagrams truncate), so it slots into any UDP relay loop.
// Relays older than 0.4.0 reject the session: they do not know the udp
// address flag.
func (c *Client) DialUDP(target Address) (net.Conn, error) {
	sk, err := c.handshake(target, true)
	if err != nil {
		return nil, err
	}
	return &UDPConn{s: sk}, nil
}

// handshake connects the transport, runs the encrypted handshake and sends
// the target address (with the udp flag when asked).
func (c *Client) handshake(target Address, udp bool) (*stream, error) {
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
	sk, err := clientHandshake(conn, c.PSK)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := WriteAddressMode(sk, target, udp); err != nil {
		sk.Close()
		return nil, err
	}
	return sk, nil
}
