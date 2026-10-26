package turnrelay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// Client dials the qulogi relay through a TURN server (RFC 5766 +
// RFC 6062). The server transport is TCP, so the flow is a handful of
// request/response exchanges — no retransmission machinery is needed.
type Client struct {
	// Server is the TURN server address (host:port); commonly :3478 for
	// plain STUN or :443 on a hardened deployment.
	Server string
	// User and Pass are the long-term credentials. Empty credentials
	// target anonymous servers.
	User string
	Pass string
	// Fingerprint appends the FINGERPRINT attribute to requests (coturn
	// checks it when fingerprint is enabled).
	Fingerprint bool
	// Timeout bounds every single request (default 5s) and the dial.
	Timeout time.Duration
	// Log receives progress lines.
	Log func(string)
}

// Alloc is the outcome of a successful Allocate.
type Alloc struct {
	// Relayed is the relayed transport address the server reserved.
	Relayed string
	// Lifetime is the allocation refresh window.
	Lifetime time.Duration

	// Credential state captured from the server challenge; reused for
	// every subsequent request of this client instance.
	key   []byte
	realm string
	nonce string
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 5 * time.Second
}

func (c *Client) logf(format string, args ...any) {
	if c.Log != nil {
		c.Log(fmt.Sprintf("turn: "+format, args...))
	}
}

// auth adds the long-term credential attributes every authenticated
// request must carry (RFC 5389 §10.2).
func (c *Client) auth(msg *Message, st *Alloc) {
	if c.User == "" {
		return
	}
	msg.Add(attrUsername, []byte(c.User))
	if st.realm != "" {
		msg.Add(attrRealm, []byte(st.realm))
	}
	if st.nonce != "" {
		msg.Add(attrNonce, []byte(st.nonce))
	}
}

// Allocate performs the allocation handshake and returns the control
// connection (kept open for Refresh) together with the allocation info.
func (c *Client) Allocate(ctx context.Context) (net.Conn, *Alloc, error) {
	d := net.Dialer{Timeout: c.timeout()}
	ctrl, err := d.DialContext(ctx, "tcp", c.Server)
	if err != nil {
		return nil, nil, fmt.Errorf("turn: server %s: %w", c.Server, err)
	}
	st, err := c.allocateOn(ctx, ctrl)
	if err != nil {
		ctrl.Close()
		return nil, nil, err
	}
	return ctrl, st, nil
}

// allocateOn runs the Allocate exchange on an established connection,
// including the 401/438 long-term credential round trip.
func (c *Client) allocateOn(ctx context.Context, ctrl net.Conn) (*Alloc, error) {
	req := NewMessage(methodAllocate, classRequest)
	req.Add(attrReqTransport, []byte{protoUDP, 0, 0, 0})
	req.Add(attrDontFragment, []byte{})
	if _, err := ctrl.Write(req.Encode(nil, c.Fingerprint)); err != nil {
		return nil, fmt.Errorf("turn: allocate: %w", err)
	}
	resp, err := readMessage(ctrl, ctxDeadline(ctx, c.timeout()))
	if err != nil {
		return nil, fmt.Errorf("turn: allocate reply: %w", err)
	}
	st := &Alloc{Lifetime: 600 * time.Second}
	if resp.Class == classError {
		code, reason := errCode(resp.Get(attrErrorCode))
		if code != 401 && code != 438 {
			return nil, fmt.Errorf("turn: allocate refused: %d %s", code, reason)
		}
		// Long-term credentials: the challenge carries realm and nonce.
		if resp.Has(attrRealm) {
			st.realm = string(resp.Get(attrRealm))
		}
		if resp.Has(attrNonce) {
			st.nonce = string(resp.Get(attrNonce))
		}
		if c.User == "" {
			return nil, errors.New("turn: server requires credentials")
		}
		st.key = LongTermKey(c.User, st.realm, c.Pass)
		c.logf("authenticating (realm %s)", st.realm)
		req = NewMessage(methodAllocate, classRequest)
		req.Add(attrReqTransport, []byte{protoUDP, 0, 0, 0})
		req.Add(attrDontFragment, []byte{})
		c.auth(req, st)
		if _, err := ctrl.Write(req.Encode(st.key, c.Fingerprint)); err != nil {
			return nil, fmt.Errorf("turn: allocate(auth): %w", err)
		}
		resp, err = readMessage(ctrl, ctxDeadline(ctx, c.timeout()))
		if err != nil {
			return nil, fmt.Errorf("turn: allocate(auth) reply: %w", err)
		}
		if resp.Class == classError {
			code, reason := errCode(resp.Get(attrErrorCode))
			return nil, fmt.Errorf("turn: allocate refused: %d %s", code, reason)
		}
	}
	if v := resp.Get(attrXORRelayedAddr); v != nil {
		if a, aerr := resp.PeerAddress(v); aerr == nil {
			st.Relayed = a
		}
	}
	if v := resp.Get(attrLifetime); len(v) == 4 {
		if lt := time.Duration(binary.BigEndian.Uint32(v)) * time.Second; lt > 0 {
			st.Lifetime = lt
		}
	}
	c.logf("allocated %s (lifetime %s)", st.Relayed, st.Lifetime.Truncate(time.Second))
	return st, nil
}

// Dial allocates and binds a TCP peer connection to peer and returns it
// as an ordinary stream. A background refresh keeps the allocation alive
// for as long as the connection lives; closing the connection releases
// the allocation. peer is the address of the qulogi relay behind the
// TURN server.
func (c *Client) Dial(peer string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout()*4)
	defer cancel()
	ctrl, st, err := c.Allocate(ctx)
	if err != nil {
		return nil, err
	}
	data, err := c.bindPeer(ctrl, st, peer)
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	conn := &Conn{Conn: data, ctrl: ctrl, done: make(chan struct{})}
	go conn.refresh(st, c)
	return conn, nil
}

// bindPeer sends the Connect request on the control connection and turns
// the second TCP connection into the raw data connection to the peer
// (RFC 6062 §4.2).
func (c *Client) bindPeer(ctrl net.Conn, st *Alloc, peer string) (net.Conn, error) {
	req := NewMessage(methodConnect, classRequest)
	pv, err := req.encodeXORAddr(peer)
	if err != nil {
		return nil, err
	}
	req.Add(attrXORPeerAddress, pv)
	c.auth(req, st)
	if _, err := ctrl.Write(req.Encode(st.key, c.Fingerprint)); err != nil {
		return nil, fmt.Errorf("turn: connect: %w", err)
	}
	resp, rerr := readMessage(ctrl, time.Now().Add(c.timeout()))
	if rerr != nil {
		return nil, fmt.Errorf("turn: connect reply: %w", rerr)
	}
	if resp.Class == classError {
		code, reason := errCode(resp.Get(attrErrorCode))
		return nil, fmt.Errorf("turn: connect refused: %d %s", code, reason)
	}
	cid := resp.Get(attrConnectionID)
	if len(cid) != 4 {
		return nil, errors.New("turn: connect reply without connection id")
	}
	d := net.Dialer{Timeout: c.timeout()}
	data, err := d.Dial("tcp", c.Server)
	if err != nil {
		return nil, fmt.Errorf("turn: data connection: %w", err)
	}
	bind := NewMessage(methodConnectionBind, classRequest)
	bind.Add(attrConnectionID, cid)
	c.auth(bind, st)
	if _, err := data.Write(bind.Encode(st.key, c.Fingerprint)); err != nil {
		data.Close()
		return nil, fmt.Errorf("turn: bind: %w", err)
	}
	bresp, berr := readMessage(data, time.Now().Add(c.timeout()))
	if berr != nil {
		data.Close()
		return nil, fmt.Errorf("turn: bind reply: %w", berr)
	}
	if bresp.Class == classError {
		code, reason := errCode(bresp.Get(attrErrorCode))
		data.Close()
		return nil, fmt.Errorf("turn: bind refused: %d %s", code, reason)
	}
	_ = data.SetReadDeadline(time.Time{})
	_ = data.SetWriteDeadline(time.Time{})
	c.logf("data connection bound to %s", peer)
	return data, nil
}

// ctxDeadline combines the context deadline with the per-request timeout.
func ctxDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		return d
	}
	return deadline
}

// Conn is a tunnel stream carried through the TURN server: reads and
// writes go to the peer TCP connection the server opened on our behalf.
type Conn struct {
	net.Conn
	ctrl   net.Conn
	done   chan struct{}
	closed bool
}

// Close releases the allocation and tears both connections down.
func (c *Conn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.done)
	if c.ctrl != nil {
		// Best-effort release with a zero-lifetime refresh.
		req := NewMessage(methodRefresh, classRequest)
		req.Add(attrLifetime, []byte{0, 0, 0, 0})
		_ = c.ctrl.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = c.ctrl.Write(req.Encode(nil, false))
		c.ctrl.Close()
	}
	return c.Conn.Close()
}

// refresh keeps the allocation alive until the connection closes. When a
// refresh fails (server restarted, allocation expired) the data
// connection is closed, which surfaces as an ordinary stream error.
func (c *Conn) refresh(st *Alloc, cl *Client) {
	lifetime := st.Lifetime
	if lifetime <= 0 {
		lifetime = 600 * time.Second
	}
	ticker := time.NewTicker(lifetime / 2)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
		}
		req := NewMessage(methodRefresh, classRequest)
		req.Add(attrLifetime, binary.BigEndian.AppendUint32(nil, uint32(lifetime/time.Second)))
		cl.auth(req, st)
		if _, err := c.ctrl.Write(req.Encode(st.key, cl.Fingerprint)); err != nil {
			cl.logf("refresh: %v", err)
			c.Conn.Close()
			return
		}
		resp, err := readMessage(c.ctrl, time.Now().Add(cl.timeout()))
		if err != nil {
			cl.logf("refresh reply: %v", err)
			c.Conn.Close()
			return
		}
		if resp.Class != classSuccess {
			code, reason := errCode(resp.Get(attrErrorCode))
			cl.logf("refresh refused: %d %s", code, reason)
			c.Conn.Close()
			return
		}
		if v := resp.Get(attrLifetime); len(v) == 4 {
			if lt := time.Duration(binary.BigEndian.Uint32(v)) * time.Second; lt > 0 {
				lifetime = lt
				ticker.Reset(lifetime / 2)
			}
		}
	}
}

// Probe is the reconnaissance primitive: a full Allocate against the
// server, measuring the round trip. The allocation is released
// immediately. Credentials are optional (anonymous servers pass empty
// user/pass).
func Probe(ctx context.Context, server, user, pass string) (time.Duration, error) {
	start := time.Now()
	cl := &Client{Server: server, User: user, Pass: pass, Timeout: 5 * time.Second}
	ctrl, alloc, err := cl.Allocate(ctx)
	if err != nil {
		return 0, err
	}
	// Release: zero-lifetime refresh, best effort.
	req := NewMessage(methodRefresh, classRequest)
	req.Add(attrLifetime, []byte{0, 0, 0, 0})
	_ = ctrl.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = ctrl.Write(req.Encode(alloc.key, false))
	ctrl.Close()
	if alloc.Relayed == "" {
		return 0, errors.New("turn: no relayed address in allocate reply")
	}
	return time.Since(start), nil
}

// ParseServer normalises a TURN server address: bare hosts get :3478.
func ParseServer(addr string) (string, error) {
	if addr == "" {
		return "", errors.New("turn: server address required")
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr, nil
	}
	return net.JoinHostPort(addr, strconv.Itoa(3478)), nil
}
