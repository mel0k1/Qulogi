package tunnel

import (
	"net"
	"time"
)

type Client struct {
	Server  string
	PSK     []byte
	Timeout time.Duration
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
