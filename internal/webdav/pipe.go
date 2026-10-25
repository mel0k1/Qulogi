package webdav

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Roles decide which mailbox side a Pipe feeds. Both sides of one session
// share the same Mailbox directory; the client writes up/ and reads down/,
// the relay does the opposite.
const (
	RoleClient = "client"
	RoleRelay  = "relay"
)

const (
	defaultChunk = 256 << 10 // 256 KiB per object
	minChunk     = 8 << 10
	maxChunk     = 4 << 20

	defaultPoll    = 2 * time.Second
	minPoll        = 250 * time.Millisecond
	chunkSuffix    = ".chunk"
	sessionPrefix  = "s-"
	sessionNameLen = len(sessionPrefix) + 12
)

// PipeConfig wires one end of a mailbox connection.
type PipeConfig struct {
	Client *Client
	// Mailbox is the session directory ("/"-separated, relative to the
	// endpoint). The client appends a unique "s-<hex>" subdirectory when
	// Session is empty; the relay addresses an existing session directly.
	Mailbox string
	// Session names an existing session subdirectory (relay side). Empty
	// means "create a new one" (client side).
	Session string
	Role    string
	// Chunk is the max object size in bytes (default 256 KiB).
	Chunk int
	// Poll is the downlink listing interval (default 2s).
	Poll time.Duration
	// Idle bounds how long the pipe may sit without delivering any data
	// before Read fails with a timeout. Zero picks a role default
	// (3 min for the client, 10 min for the relay); negative disables it.
	Idle time.Duration
	// Log receives human readable events.
	Log func(string)
}

// Pipe is a net.Conn whose byte stream is carried as small objects under
// <mailbox>/<up|down> on a WebDAV server. The write side pushes chunks
// (PUT); the read side polls a listing and downloads new chunks in order,
// deleting each one after consuming it. It satisfies the tunnel package:
// the encrypted frame stream just flows through unmodified.
type Pipe struct {
	cfg     PipeConfig
	client  *Client
	session string
	upPath  string
	dnPath  string

	wmu       sync.Mutex
	wbuf      []byte
	wseq      uint64
	closed    chan struct{}
	closeOnce sync.Once

	rmu       sync.Mutex
	rbuf      []byte
	wantSeq   uint64
	consumed  map[uint64]bool
	listFails int
	deadline  time.Time // user deadline from SetReadDeadline
	idleAt    time.Time // internal inactivity deadline
	lastError error
}

// OpenPipe prepares the mailbox collections and returns the connection.
func OpenPipe(cfg PipeConfig) (*Pipe, error) {
	if cfg.Client == nil {
		return nil, errors.New("webdav: client required")
	}
	if cfg.Role != RoleClient && cfg.Role != RoleRelay {
		return nil, fmt.Errorf("webdav: bad role %q", cfg.Role)
	}
	if cfg.Chunk == 0 {
		cfg.Chunk = defaultChunk
	}
	cfg.Chunk = clamp(cfg.Chunk, minChunk, maxChunk)
	if cfg.Poll == 0 {
		cfg.Poll = defaultPoll
	}
	cfg.Poll = clampDur(cfg.Poll, minPoll, time.Minute)
	if cfg.Idle == 0 {
		if cfg.Role == RoleClient {
			cfg.Idle = 3 * time.Minute
		} else {
			cfg.Idle = 10 * time.Minute
		}
	}
	if cfg.Idle > 0 {
		cfg.Idle = clampDur(cfg.Idle, 10*time.Second, time.Hour)
	}

	session := strings.Trim(cfg.Session, "/")
	if session == "" {
		rnd := make([]byte, 6)
		if _, err := randomBytes(rnd); err != nil {
			return nil, err
		}
		session = sessionPrefix + hex.EncodeToString(rnd)
	}
	base := strings.Trim(cfg.Mailbox, "/")
	p := &Pipe{
		cfg:      cfg,
		client:   cfg.Client,
		session:  session,
		upPath:   base + "/" + session + "/up",
		dnPath:   base + "/" + session + "/down",
		closed:   make(chan struct{}),
		consumed: map[uint64]bool{},
	}
	p.refreshIdle()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, dir := range []string{base + "/" + session, p.upPath, p.dnPath} {
		if err := p.client.MkdirAll(ctx, dir); err != nil {
			return nil, fmt.Errorf("webdav: create %s: %w", dir, err)
		}
	}
	p.logf("webdav: mailbox %s ready (role %s)", base+"/"+session, cfg.Role)
	return p, nil
}

// SessionName returns the session subdirectory name of this pipe.
func (p *Pipe) SessionName() string {
	return p.session
}

func (p *Pipe) writeDir() string {
	if p.cfg.Role == RoleClient {
		return p.upPath
	}
	return p.dnPath
}

func (p *Pipe) readDir() string {
	if p.cfg.Role == RoleClient {
		return p.dnPath
	}
	return p.upPath
}

// --- net.Conn: write side ---

// Write appends to the stream and PUTs it as one chunk before returning.
// Every Write is visible to the peer after Write returns: the tunnel
// handshake is request-response and a buffered salt would deadlock both
// sides. Large writes split into Chunk-sized objects.
func (p *Pipe) Write(b []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	p.wmu.Lock()
	defer p.wmu.Unlock()
	sent := 0
	for len(b) > 0 {
		n := min(p.cfg.Chunk-len(p.wbuf), len(b))
		p.wbuf = append(p.wbuf, b[:n]...)
		b = b[n:]
		sent += n
		if err := p.flush(); err != nil {
			return sent, err
		}
	}
	return sent, nil
}

// flush PUTs the buffered bytes as the next chunk (wmu held).
func (p *Pipe) flush() error {
	if len(p.wbuf) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	name := fmt.Sprintf("%012d%s", p.wseq, chunkSuffix)
	if err := p.client.Put(ctx, p.writeDir()+"/"+name, p.wbuf); err != nil {
		return fmt.Errorf("webdav: put %s: %w", name, err)
	}
	p.wseq++
	p.wbuf = p.wbuf[:0]
	return nil
}

// --- net.Conn: read side ---

func (p *Pipe) Read(b []byte) (int, error) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	for {
		if len(p.rbuf) > 0 {
			n := copy(b, p.rbuf)
			p.rbuf = p.rbuf[n:]
			p.refreshIdle()
			return n, nil
		}
		if p.lastError != nil {
			return 0, p.lastError
		}
		select {
		case <-p.closed:
			return 0, net.ErrClosed
		default:
		}
		if p.idleExpired() {
			return 0, os.ErrDeadlineExceeded
		}
		if err := p.pollOnce(); err != nil {
			return 0, err
		}
		if len(p.rbuf) == 0 {
			if derr := p.waitRead(); derr != nil {
				return 0, derr
			}
		}
	}
}

// refreshIdle pushes the inactivity deadline out after progress.
func (p *Pipe) refreshIdle() {
	if p.cfg.Idle > 0 {
		p.idleAt = time.Now().Add(p.cfg.Idle)
	}
}

func (p *Pipe) idleExpired() bool {
	return p.cfg.Idle > 0 && !p.idleAt.IsZero() && time.Now().After(p.idleAt)
}

// pollOnce lists the read mailbox once and downloads every consecutive
// new chunk into rbuf (rmu held).
func (p *Pipe) pollOnce() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	names, err := p.client.List(ctx, p.readDir())
	if err != nil && !errors.Is(err, ErrNotFound) {
		// A flaky listing must not kill the connection: report only after
		// two consecutive failures.
		p.listFails++
		if p.listFails < 2 {
			return nil
		}
		return fmt.Errorf("webdav: list %s: %w", p.readDir(), err)
	}
	p.listFails = 0

	type chunk struct {
		seq  uint64
		name string
	}
	var fresh []chunk
	for _, n := range names {
		if !strings.HasSuffix(n, chunkSuffix) {
			continue
		}
		seq, perr := strconv.ParseUint(strings.TrimSuffix(n, chunkSuffix), 10, 64)
		if perr != nil {
			continue
		}
		if seq >= p.wantSeq && !p.consumed[seq] {
			fresh = append(fresh, chunk{seq: seq, name: n})
		}
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].seq < fresh[j].seq })

	for _, c := range fresh {
		if c.seq != p.wantSeq {
			// Gap: the listing is eventually consistent, wait for the
			// missing chunk instead of downloading out of order.
			break
		}
		data, gerr := p.client.Get(ctx, p.readDir()+"/"+c.name)
		if gerr != nil {
			if errors.Is(gerr, ErrNotFound) {
				return nil // listing raced a purge, try again later
			}
			return fmt.Errorf("webdav: get %s: %w", c.name, gerr)
		}
		p.rbuf = append(p.rbuf, data...)
		p.wantSeq++
		p.consumed[c.seq] = true
		// Best-effort delete: the consumed map protects against repeats
		// even when the DELETE fails.
		_ = p.client.Delete(ctx, p.readDir()+"/"+c.name)
	}
	return nil
}

// waitRead sleeps one poll interval unless a deadline expires first
// (rmu held).
func (p *Pipe) waitRead() error {
	if p.idleExpired() {
		return os.ErrDeadlineExceeded
	}
	if !p.deadline.IsZero() && time.Now().After(p.deadline) {
		return os.ErrDeadlineExceeded
	}
	timer := time.NewTimer(p.cfg.Poll)
	defer timer.Stop()
	select {
	case <-p.closed:
		return net.ErrClosed
	case <-timer.C:
	}
	if p.idleExpired() {
		return os.ErrDeadlineExceeded
	}
	if !p.deadline.IsZero() && time.Now().After(p.deadline) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

// --- net.Conn: lifecycle ---

// Close flushes the write buffer and stops the read side. Both peers may
// then clean their halves best-effort (relay deletes the session dir).
func (p *Pipe) Close() error {
	var err error
	p.closeOnce.Do(func() {
		p.wmu.Lock()
		err = p.flush()
		p.wmu.Unlock()
		close(p.closed)
	})
	return err
}

// Cleanup removes the session directory. Call it when done with the pipe
// (the relay cleans after every session; the client usually leaves the
// mailbox behind so the relay can finish delivering the last chunks).
func (p *Pipe) Cleanup() error {
	dir := strings.TrimSuffix(p.upPath, "/up")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return p.client.Delete(ctx, dir)
}

func (p *Pipe) LocalAddr() net.Addr  { return mailboxAddr{"webdav-mailbox"} }
func (p *Pipe) RemoteAddr() net.Addr { return mailboxAddr{"webdav-mailbox"} }

// SetReadDeadline bounds a Read call. The zero value removes the deadline.
func (p *Pipe) SetReadDeadline(t time.Time) error {
	p.rmu.Lock()
	p.deadline = t
	p.rmu.Unlock()
	return nil
}

func (p *Pipe) SetWriteDeadline(time.Time) error { return nil } // PUTs use their own ctx timeout

func (p *Pipe) SetDeadline(t time.Time) error { return p.SetReadDeadline(t) }

func (p *Pipe) logf(format string, args ...any) {
	if p.cfg.Log != nil {
		p.cfg.Log(fmt.Sprintf(format, args...))
	}
}

type mailboxAddr struct{ network string }

func (a mailboxAddr) Network() string { return a.network }
func (a mailboxAddr) String() string  { return "webdav" }

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampDur(v, lo, hi time.Duration) time.Duration {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func randomBytes(b []byte) (int, error) {
	return rand.Read(b)
}
