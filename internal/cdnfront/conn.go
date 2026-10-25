package cdnfront

import (
	"bufio"
	"net"

	"github.com/mel0k1/qulogi/internal/tunnel"
)

// bufferedConn serves bytes an HTTP parser already consumed before reading
// the underlying stream. bufio.Reader reads through to the connection once
// its buffer is empty, so a single delegation covers both cases; only
// Write/deadlines hit the raw conn.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// accept runs the tunnel server side over a connection whose head may have
// been consumed by the HTTP parser (replayed through br).
func accept(conn net.Conn, br *bufio.Reader, psk []byte, log func(string)) error {
	wrapped := conn
	if br != nil {
		wrapped = &bufferedConn{Conn: conn, r: br}
	}
	return tunnel.AcceptSession(wrapped, psk, log)
}
