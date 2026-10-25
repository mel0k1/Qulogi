package transport

import (
        "errors"
        "io"
        "net"
        "sync"
        "time"
)

// ClientOpts configures the client side of the camouflage.
type ClientOpts struct {
        // SNI is the hostname advertised in the fake ClientHello. Use a domain
        // that is reachable (whitelisted) from the client's network so that DPI
        // treats the flow as allowed-platform traffic.
        SNI string
        // FakeCH disables the ClientHello flight entirely when false (plain
        // record framing only).
        FakeCH bool
        // Split forces a small pause between the ClientHello record and the
        // first application-data record so they leave as separate TCP segments.
        Split bool
}

var tlsVersion = []byte{0x03, 0x03}

// CamoConn is a net.Conn that frames all traffic in TLS-like records.
// Handshake records (0x16) and ChangeCipherSpec (0x14) are camouflage and
// are discarded on read; application data (0x17) is passed through.
type CamoConn struct {
        conn net.Conn

        rmu    sync.Mutex
        rbuf   []byte
        rdErr  error

        wmu sync.Mutex

        closeOnce sync.Once
}

// NewCamoClient wraps conn for the client role: it emits the fake
// ClientHello immediately and then keeps the stream in record framing.
func NewCamoClient(conn net.Conn, opts ClientOpts) (*CamoConn, error) {
        if tc, ok := conn.(*net.TCPConn); ok {
                _ = tc.SetNoDelay(true)
        }
        c := &CamoConn{conn: conn}
        if opts.FakeCH {
                ch := BuildClientHello(opts.SNI)
                if _, err := conn.Write(ch); err != nil {
                        return nil, err
                }
                if opts.Split {
                        jitterPause()
                }
        }
        return c, nil
}

// NewCamoServer wraps conn for the server role: it swallows the camouflage
// flight from the client and answers with a fake ServerHello + CCS so the
// flow looks like a completed TLS handshake to passive observers.
func NewCamoServer(conn net.Conn) (*CamoConn, error) {
        c := &CamoConn{conn: conn}
        // Drain handshake records the client sent before the salt exchange.
        if err := c.drainHandshake(); err != nil {
                return nil, err
        }
        for _, rec := range fakeServerFlight() {
                if _, err := conn.Write(rec); err != nil {
                        return nil, err
                }
        }
        return c, nil
}

// WrapServer sniffs the first bytes of a fresh connection: TLS-shaped
// streams get the camouflage treatment, anything else is passed through
// unchanged (legacy tunnel framing).
func WrapServer(conn net.Conn) (net.Conn, bool /* camo */, error) {
        var peek [recHeaderSize]byte
        n, err := io.ReadFull(conn, peek[:])
        if err != nil && err != io.ErrUnexpectedEOF {
                return conn, false, err
        }
        head := peek[:n]
        if looksLikeTLS(head) {
                pushback := &pushbackConn{Conn: conn, prefix: head}
                c, cerr := NewCamoServer(pushback)
                return c, true, cerr
        }
        return &pushbackConn{Conn: conn, prefix: head}, false, nil
}

func (c *CamoConn) drainHandshake() error {
        var discarded int
        for {
                ctype, payload, err := readRecord(c.conn)
                if err != nil {
                        return err
                }
                discarded += len(payload)
                if discarded > maxHandshakeDiscard {
                        return errors.New("transport: camouflage flight too long")
                }
                switch ctype {
                case recHandshake, recChangeCipherSpec, recAlert:
                        if ctype == recHandshake && len(payload) > 0 && payload[0] == 0x01 {
                                // ClientHello seen; the next records carry the salt.
                                continue
                        }
                        continue
                case recAppData:
                        c.rbuf = payload
                        return nil
                default:
                        continue
                }
        }
}

// Write frames p as one or more TLS application-data records.
func (c *CamoConn) Write(p []byte) (int, error) {
        c.wmu.Lock()
        defer c.wmu.Unlock()
        sent := 0
        for sent < len(p) {
                end := sent + maxRecordPayload
                if end > len(p) {
                        end = len(p)
                }
                buf := appendRecord(nil, p[sent:end], recAppData, tlsVersion)
                if _, err := c.conn.Write(buf); err != nil {
                        return sent, err
                }
                sent = end
        }
        return sent, nil
}

// Read returns payload bytes from application-data records, silently
// skipping camouflage records from the peer.
func (c *CamoConn) Read(p []byte) (int, error) {
        c.rmu.Lock()
        defer c.rmu.Unlock()
        for {
                if len(c.rbuf) > 0 {
                        n := copy(p, c.rbuf)
                        c.rbuf = c.rbuf[n:]
                        return n, nil
                }
                if c.rdErr != nil {
                        return 0, c.rdErr
                }
                ctype, payload, err := readRecord(c.conn)
                if err != nil {
                        if err == io.EOF {
                                err = io.EOF
                        }
                        c.rdErr = err
                        return 0, err
                }
                switch ctype {
                case recAppData:
                        c.rbuf = payload
                case recHandshake, recChangeCipherSpec, recAlert:
                        continue // camouflage or peer-side noise
                default:
                        continue
                }
        }
}

func (c *CamoConn) Close() error {
        var err error
        c.closeOnce.Do(func() { err = c.conn.Close() })
        return err
}

func (c *CamoConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *CamoConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *CamoConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *CamoConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *CamoConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// pushbackConn replays bytes peeked during protocol detection before any
// read from the underlying connection.
type pushbackConn struct {
        net.Conn
        prefix []byte
        mu     sync.Mutex
}

func (p *pushbackConn) Read(b []byte) (int, error) {
        p.mu.Lock()
        if len(p.prefix) > 0 {
                n := copy(b, p.prefix)
                p.prefix = p.prefix[n:]
                p.mu.Unlock()
                return n, nil
        }
        p.mu.Unlock()
        return p.Conn.Read(b)
}
