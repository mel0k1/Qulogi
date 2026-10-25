package discover

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
)

// ErrNoAddress reports that a transport address is empty after parsing.
var ErrNoAddress = errors.New("discover: transport address is empty")

// dialAddr converts a transport address into a dialable host:port. URL-style
// addresses (storage relays) are reduced to their host and default port.
func dialAddr(t Transport) (string, error) {
	addr := t.Addr
	if strings.Contains(addr, "://") {
		u, err := url.Parse(addr)
		if err != nil {
			return "", err
		}
		addr = u.Host
		if addr != "" && !strings.Contains(addr, ":") {
			switch u.Scheme {
			case "https":
				addr += ":443"
			case "http":
				addr += ":80"
			}
		}
	}
	if addr == "" {
		return "", ErrNoAddress
	}
	return addr, nil
}

// Probe measures pure TCP dial latency to a transport. This is a cheap,
// uniform liveness signal that works for every tcp-backed transport;
// adapter-specific health checks live with the adapters themselves.
func Probe(ctx context.Context, t Transport) (time.Duration, error) {
	addr, err := dialAddr(t)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	c.Close()
	return time.Since(start), nil
}
