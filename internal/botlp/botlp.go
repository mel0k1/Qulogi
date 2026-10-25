// Package botlp implements the bot-longpoll transport class from
// docs/RELAY_DISCOVERY.md (M5): tunnel frames carried as JSON messages
// through the long-poll API of a whitelisted platform.
//
//	device ──HTTPS──► platform bot API ◄──long-poll── relay
//
// Both sides speak only official API calls to the whitelisted platform, so
// nothing in the traffic pattern deviates from ordinary bot messaging — no
// relay address is visible anywhere. Latency is seconds (poll interval);
// throughput is bounded by the platform's message size limits, so frames
// travel base64-encoded in chunks. The transport targets browsing, RSS and
// mail as a fallback when WebDAV and cdn-front are unavailable.
//
// The platform contract is deliberately generic so any bot API (VK, Max,
// a community bridge, a self-hosted glue) can be mapped onto it with a
// thin shim:
//
//	POST {base}/send          {"token":"…","room":"…","data":"<base64>"}
//	                          → 200 {"ok":true}          (FIFO per room)
//	GET  {base}/poll          ?token=…&room=…&seq=N&wait=25
//	                          → 200 {"seq":M,"frames":["<base64>",…]}
//	                            (long-poll: answers as soon as frames with
//	                             seq > N exist, or after wait seconds)
//
// A control room carries session advertisements ("open:<room>"); every
// session's frames ride its own room, so a single control poll serves any
// number of concurrent flows.
package botlp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// Limits mirror typical bot API constraints (VK caps messages at 4096
// characters, so the default stays conservative).
const (
	defaultChunk = 96 << 10 // 96 KiB of payload per message (before base64)
	minChunk     = 4 << 10
	maxChunk     = 256 << 10

	defaultPollWait = 25              // seconds a long-poll may park server-side
	defaultIdle     = 3 * time.Minute // client role
	relayIdle       = 10 * time.Minute

	controlSuffix = "-ctl"
	replySuffix   = "-r"
	sessionPrefix = "room-"
)

// Errors surfaced to callers.
var (
	ErrNotFound = errors.New("botlp: room not found")
)

// Platform is the HTTP face of the whitelisted platform API.
type Platform struct {
	Base   string       // e.g. https://api.example.org/bot
	Token  string       // shared bot token
	HTTP   *http.Client // nil → client with sane timeouts
	chunk  int
	pollWt int
}

// NewPlatform validates the API base and returns a platform handle.
func NewPlatform(base, token string) (*Platform, error) {
	if base == "" {
		return nil, errors.New("botlp: platform base url required")
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("botlp: bad platform base %q", base)
	}
	return &Platform{
		Base:   base,
		Token:  token,
		HTTP:   &http.Client{Timeout: 90 * time.Second},
		chunk:  defaultChunk,
		pollWt: defaultPollWait,
	}, nil
}

type sendReq struct {
	Token string `json:"token"`
	Room  string `json:"room"`
	Data  string `json:"data"`
}

type pollResp struct {
	Seq    uint64   `json:"seq"`
	Frames []string `json:"frames"`
}

// Send posts one frame to the room.
func (p *Platform) Send(ctx context.Context, room string, data []byte) error {
	body, err := json.Marshal(sendReq{
		Token: p.Token,
		Room:  room,
		Data:  base64.StdEncoding.EncodeToString(data),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Base+"/send", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return p.do(req, http.StatusOK, nil)
}

// Poll long-polls the room: it returns once frames with seq greater than
// the given one exist (or after the server-side wait elapses), together
// with the new cursor.
func (p *Platform) Poll(ctx context.Context, room string, seq uint64) (uint64, [][]byte, error) {
	q := url.Values{}
	q.Set("token", p.Token)
	q.Set("room", room)
	q.Set("seq", fmt.Sprint(seq))
	q.Set("wait", fmt.Sprint(p.pollWt))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Base+"/poll?"+q.Encode(), nil)
	if err != nil {
		return seq, nil, err
	}
	var pr pollResp
	if err := p.do(req, http.StatusOK, &pr); err != nil {
		return seq, nil, err
	}
	var out [][]byte
	for _, f := range pr.Frames {
		raw, err := base64.StdEncoding.DecodeString(f)
		if err != nil {
			return seq, out, fmt.Errorf("botlp: bad frame: %w", err)
		}
		out = append(out, raw)
	}
	return pr.Seq, out, nil
}

func (p *Platform) do(req *http.Request, want int, out any) error {
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("botlp: http %d: %s", resp.StatusCode, string(body))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// NewRoom returns a fresh session room name.
func NewRoom() (string, error) {
	rnd := make([]byte, 8)
	if _, err := rand.Read(rnd); err != nil {
		return "", err
	}
	return sessionPrefix + hex.EncodeToString(rnd), nil
}

// ControlRoom derives the control room from the operator's base room.
func ControlRoom(base string) string { return base + controlSuffix }

// Roles decide which half of the session mailbox a pipe feeds. The client
// writes the session room and reads the reply room; the relay does the
// opposite — so neither side ever consumes its own frames.
const (
	RoleClient = "client"
	RoleRelay  = "relay"
)

// Pipe is a net.Conn over the platform: writes go out as frames in the
// session room, reads come from long-polling the reply room.
type PipeConfig struct {
	Platform *Platform
	// Role selects the mailbox halves (default client).
	Role string
	// Room is the session name both sides of the connection agree on.
	Room string
	// Control is the control room to announce the session into (client
	// side). Empty defaults to ControlRoom(Room), which is only right when
	// Room already is the operator's base room.
	Control string
	// Chunk is the max frame payload in bytes (default 96 KiB).
	Chunk int
	// Idle bounds how long the pipe may sit without delivering data
	// before Read fails (default 3 min client, 10 min relay; negative
	// disables).
	Idle time.Duration
	// Ctx cancels in-flight long-polls when the owner shuts the session
	// down (relay lifecycle). Nil means context.Background().
	Ctx context.Context
	Log func(string)
}

type Pipe struct {
	cfg    PipeConfig
	p      *Platform
	ctx    context.Context
	cancel context.CancelFunc

	wmu       sync.Mutex
	closed    chan struct{}
	closeOnce sync.Once

	rmu      sync.Mutex
	rbuf     []byte
	seq      uint64
	deadline time.Time // user deadline
	idleAt   time.Time
	lastErr  error
}

// OpenPipe prepares the session mailbox. The client side announces the
// session to the control room so the relay picks it up.
func OpenPipe(cfg PipeConfig, announce bool) (*Pipe, error) {
	if cfg.Platform == nil {
		return nil, errors.New("botlp: platform required")
	}
	if cfg.Room == "" {
		return nil, errors.New("botlp: room required")
	}
	if cfg.Role != RoleRelay {
		cfg.Role = RoleClient
	}
	if cfg.Chunk == 0 {
		cfg.Chunk = defaultChunk
	}
	cfg.Chunk = clamp(cfg.Chunk, minChunk, maxChunk)
	if cfg.Idle == 0 {
		if cfg.Role == RoleClient {
			cfg.Idle = defaultIdle
		} else {
			cfg.Idle = relayIdle
		}
	}
	if cfg.Idle > 0 {
		cfg.Idle = clampDur(cfg.Idle, 10*time.Second, time.Hour)
	}
	base := cfg.Ctx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithCancel(base)
	p := &Pipe{cfg: cfg, p: cfg.Platform, ctx: ctx, cancel: cancel, closed: make(chan struct{})}
	p.refreshIdle()
	if announce {
		ctl := p.cfg.Control
		if ctl == "" {
			ctl = ControlRoom(p.cfg.Room)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := p.p.Send(ctx, ctl, []byte("open:"+p.cfg.Room)); err != nil {
			return nil, fmt.Errorf("botlp: announce: %w", err)
		}
	}
	return p, nil
}

func (p *Pipe) SessionRoom() string { return p.cfg.Room }

// writeRoom is the mailbox half this pipe pushes frames into; readRoom is
// the half it long-polls. Client: session room / reply room. Relay: the
// reverse.
func (p *Pipe) writeRoom() string {
	if p.cfg.Role == RoleClient {
		return p.cfg.Room
	}
	return p.cfg.Room + replySuffix
}

func (p *Pipe) readRoom() string {
	if p.cfg.Role == RoleClient {
		return p.cfg.Room + replySuffix
	}
	return p.cfg.Room
}

// --- net.Conn: write side ---

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
		n := min(p.cfg.Chunk, len(b))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := p.p.Send(ctx, p.writeRoom(), b[:n])
		cancel()
		if err != nil {
			return sent, fmt.Errorf("botlp: send: %w", err)
		}
		b = b[n:]
		sent += n
	}
	return sent, nil
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
		if p.lastErr != nil {
			return 0, p.lastErr
		}
		select {
		case <-p.closed:
			return 0, net.ErrClosed
		default:
		}
		if p.idleExpired() {
			return 0, os.ErrDeadlineExceeded
		}
		if !p.deadline.IsZero() && time.Now().After(p.deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		// One long-poll round; the platform parks the request until frames
		// arrive or the server-side wait elapses. Close() cancels it.
		ctx := p.ctx
		if !p.deadline.IsZero() {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, p.deadline)
			defer cancel()
		}
		seq, frames, err := p.p.Poll(ctx, p.readRoom(), p.seq)
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return 0, fmt.Errorf("botlp: poll: %w", err)
		}
		p.seq = seq
		for _, f := range frames {
			p.rbuf = append(p.rbuf, f...)
		}
		p.refreshIdle()
	}
}

// Close stops the pipe. The relay cleans its session bookkeeping; the
// platform rooms age out on their own.
func (p *Pipe) Close() error {
	p.closeOnce.Do(func() {
		close(p.closed)
		p.cancel() // abort an in-flight long-poll immediately
	})
	return nil
}

func (p *Pipe) LocalAddr() net.Addr  { return botlpAddr{} }
func (p *Pipe) RemoteAddr() net.Addr { return botlpAddr{} }

func (p *Pipe) SetReadDeadline(t time.Time) error {
	p.rmu.Lock()
	p.deadline = t
	p.rmu.Unlock()
	return nil
}

func (p *Pipe) SetWriteDeadline(time.Time) error { return nil }
func (p *Pipe) SetDeadline(t time.Time) error    { return p.SetReadDeadline(t) }

func (p *Pipe) refreshIdle() {
	if p.cfg.Idle > 0 {
		p.idleAt = time.Now().Add(p.cfg.Idle)
	}
}

func (p *Pipe) idleExpired() bool {
	return p.cfg.Idle > 0 && !p.idleAt.IsZero() && time.Now().After(p.idleAt)
}

type botlpAddr struct{}

func (botlpAddr) Network() string { return "botlp" }
func (botlpAddr) String() string  { return "botlp-room" }

// --- helpers ---

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
