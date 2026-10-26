package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mel0k1/qulogi/internal/botlp"
	"github.com/mel0k1/qulogi/internal/dpi"
	"github.com/mel0k1/qulogi/internal/route"
	"github.com/mel0k1/qulogi/internal/socks5"
	"github.com/mel0k1/qulogi/internal/transport"
	"github.com/mel0k1/qulogi/internal/tunnel"
	"github.com/mel0k1/qulogi/internal/webdav"
)

// Per-flow egress decisions shared by the VPN sniffing layer and the
// engine dialer.
const (
	ViaDirect = "direct"
	ViaTunnel = "tunnel"
	ViaDrop   = "drop"
)

type Mode string

const (
	ModeTunnel Mode = "tunnel"
	ModeDPI    Mode = "dpi"
	// ModeVPN means the transport layer (mobile bindings) feeds packets
	// from the platform TUN device into Engine.DialContext; there is no
	// SOCKS5 listener in this mode.
	ModeVPN Mode = "vpn"
)

type Config struct {
	Mode   Mode   `json:"mode"`
	Listen string `json:"listen"`
	Server string `json:"server,omitempty"`
	PSK    string `json:"psk,omitempty"`
	Split  int    `json:"split,omitempty"`
	// Multi enables an extra ClientHello split (zapret-style multisplit).
	Multi bool `json:"multi_split,omitempty"`
	// Camo enables TLS-shaped camouflage of the tunnel connection.
	Camo bool `json:"camo,omitempty"`
	// SNI is the whitelisted domain claimed in the camouflage ClientHello.
	SNI string `json:"sni,omitempty"`
	// FakeCH sends the camouflage ClientHello as its own record/segment.
	FakeCH bool `json:"fake_ch,omitempty"`
	// SmartSplit enables the smart split: whitelisted destinations
	// (embedded list + Direct rules, minus Proxy rules) bypass the tunnel
	// and go straight out. Only meaningful when a server/relay exists.
	SmartSplit bool `json:"smart_split,omitempty"`
	// Direct adds always-direct rules (domains or CIDRs) on top of the
	// embedded whitelist.
	Direct []string `json:"direct,omitempty"`
	// Proxy forces rules through the tunnel even when they are whitelisted.
	Proxy []string `json:"proxy,omitempty"`
	// Protect (Android) marks sockets so they bypass the VPN interface.
	Protect func(int32) bool `json:"-"`
	Log     func(string)     `json:"-"`

	// CDN fronting (M4): the client talks TLS to a whitelisted CDN
	// edge while the inner Host header routes to the relay parked
	// behind the same CDN. Takes priority over botlp/DAV and the
	// plain TCP server; camouflage is pointless (the edge speaks real
	// TLS with a WebPKI certificate).
	CDNEdge string `json:"cdn_edge,omitempty"`
	CDNSNI  string `json:"cdn_sni,omitempty"`
	CDNHost string `json:"cdn_host,omitempty"`
	// CDNWS switches the CDN transport to the RFC 6455 WebSocket upgrade
	// used with real CDN networks (see internal/cdnfront).
	CDNWS bool `json:"cdn_ws,omitempty"`

	// Bot long-poll transport (M5): tunnel frames ride the long-poll
	// API of a whitelisted platform (the botlp contract in
	// internal/botlp). BotLPURL is the platform API base, BotLPRoom is
	// the operator's base room — sessions announce on <base>-ctl.
	BotLPURL   string `json:"botlp_url,omitempty"`
	BotLPToken string `json:"botlp_token,omitempty"`
	BotLPRoom  string `json:"botlp_room,omitempty"`
	// BotLPKind selects the platform adapter: "" (generic send/poll
	// contract), "vk" (VK bot API) or "max" (Max bot API). BotLPChat is
	// the peer/chat id the bridges deliver frames to.
	BotLPKind string `json:"botlp_kind,omitempty"`
	BotLPChat string `json:"botlp_chat,omitempty"`

	// WebDAV storage transport ("device → whitelisted cloud → relay"):
	// when DAVURL is set, tunnel sessions ride through WebDAV mailboxes
	// instead of a direct TCP connection to Server. Server may then stay
	// empty. Latency is seconds — for browsing, RSS and mail.
	DAVURL     string `json:"dav_url,omitempty"`
	DAVUser    string `json:"dav_user,omitempty"`
	DAVPass    string `json:"dav_pass,omitempty"`
	DAVMailbox string `json:"dav_mailbox,omitempty"`

	// TURN relay transport: tunnel frames ride a TCP peer connection
	// allocated through a TURN server (RFC 5766 + RFC 6062, see
	// internal/turnrelay). TURNServer is the TURN endpoint, Server stays
	// the relay address the allocation connects to. TURN servers exist
	// for WebRTC, so they are reachable from most filtered networks.
	TURNServer string `json:"turn_server,omitempty"`
	TURNUser   string `json:"turn_user,omitempty"`
	TURNPass   string `json:"turn_pass,omitempty"`

	// Auto-failover: Fallbacks lists reserve transports tried when the
	// primary degrades; the monitor probes and returns to the best one
	// when it recovers.
	Fallbacks []TransportSpec `json:"fallbacks,omitempty"`
	// NoFailover disables the monitor and the sticky switching.
	NoFailover bool `json:"no_failover,omitempty"`
	// FailoverProbeSecs is the monitor interval; 0 = 15s.
	FailoverProbeSecs int `json:"failover_probe_secs,omitempty"`
}

type Status struct {
	Running     bool   `json:"running"`
	Mode        string `json:"mode"`
	Listen      string `json:"listen"`
	Server      string `json:"server,omitempty"`
	Connections int64  `json:"connections"`
	BytesUp     int64  `json:"bytes_up"`
	BytesDown   int64  `json:"bytes_down"`
	Uptime      int64  `json:"uptime"`
	// Transport is the active transport (failover chain head).
	Transport string `json:"transport,omitempty"`
	// Failovers counts degradation switches since start.
	Failovers int64 `json:"failovers"`
}

type Engine struct {
	cfg   Config
	route *route.Table

	mu         sync.Mutex
	listener   net.Listener
	listenAddr string
	running    bool
	started    time.Time

	// Failover chain (see failover.go); guarded by mu.
	cands []candidate
	cur   int
	fails []int
	cool  []time.Time

	monitorOnce sync.Once
	stopMon     chan struct{}

	conns     atomic.Int64
	up        atomic.Int64
	down      atomic.Int64
	failovers atomic.Int64
}

func New(cfg Config) *Engine {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:1080"
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeDPI
	}
	e := &Engine{cfg: cfg, stopMon: make(chan struct{})}
	if cfg.SmartSplit {
		e.route = route.Default()
		e.route.AddDirect(cfg.Direct...)
		e.route.AddProxy(cfg.Proxy...)
	}
	e.cands = e.buildCandidates()
	e.fails = make([]int, len(e.cands))
	e.cool = make([]time.Time, len(e.cands))
	return e
}

func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return errors.New("engine: already running")
	}
	switch e.cfg.Mode {
	case ModeTunnel:
		if e.cfg.Server == "" && e.cfg.DAVURL == "" && e.cfg.CDNEdge == "" && e.cfg.BotLPURL == "" && e.cfg.TURNServer == "" && len(e.cfg.Fallbacks) == 0 {
			return errors.New("engine: server required in tunnel mode")
		}
		if e.cfg.PSK == "" {
			return errors.New("engine: psk required in tunnel mode")
		}
		if e.cfg.TURNServer != "" && e.cfg.Server == "" {
			return errors.New("engine: turn transport needs the relay server address")
		}
		if _, _, berr := botlp.BuildAPI(e.cfg.BotLPKind, e.cfg.BotLPURL, e.cfg.BotLPToken, e.cfg.BotLPRoom, e.cfg.BotLPChat); e.cfg.BotLPURL != "" && berr != nil {
			return berr
		}
		if err := e.validateFallbacks(); err != nil {
			return err
		}
		if len(e.cands) == 0 {
			return errors.New("engine: no usable transport")
		}
	case ModeDPI:
	case ModeVPN:
		return errors.New("engine: vpn mode is driven via DialContext, not Start")
	default:
		return fmt.Errorf("engine: unknown mode %q", e.cfg.Mode)
	}
	ln, err := net.Listen("tcp", e.cfg.Listen)
	if err != nil {
		return err
	}
	// Report the actual bound address: "127.0.0.1:0" in Status is noise.
	e.listenAddr = ln.Addr().String()
	srv := &socks5.Server{
		Listener: ln,
		Dial:     e.dial,
		Pump:     e.pump,
		Log:      e.plainLog,
	}
	e.listener = ln
	e.running = true
	e.started = time.Now()
	go func() {
		srv.Serve()
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
	}()
	e.logf("started mode=%s listen=%s", e.cfg.Mode, e.cfg.Listen)
	return nil
}

func (e *Engine) Stop() {
	e.monitorOnce.Do(func() { close(e.stopMon) })
	e.mu.Lock()
	ln := e.listener
	e.listener = nil
	e.listenAddr = ""
	e.mu.Unlock()
	if ln != nil {
		ln.Close()
		e.logf("stopped")
	}
}

func (e *Engine) Status() Status {
	e.mu.Lock()
	running := e.running
	started := e.started
	listenAddr := e.listenAddr
	e.mu.Unlock()
	listen := e.cfg.Listen
	if listenAddr != "" {
		listen = listenAddr
	}
	st := Status{
		Running:     running,
		Mode:        string(e.cfg.Mode),
		Listen:      listen,
		Server:      e.cfg.Server,
		Connections: e.conns.Load(),
		BytesUp:     e.up.Load(),
		BytesDown:   e.down.Load(),
		Transport:   e.TransportName(),
		Failovers:   e.failovers.Load(),
	}
	if running {
		st.Uptime = int64(time.Since(started).Seconds())
	}
	return st
}

// Counters exposes the byte counters for the VPN transport layer.
func (e *Engine) Counters() (up, down *atomic.Int64) {
	return &e.up, &e.down
}

// DialContext is the public dialer used by the VPN transport layer.
func (e *Engine) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return e.dial(ctx, network, addr)
}

// camoOpts builds the TLS camouflage options for plain tcp candidates.
func (e *Engine) camoOpts() *transport.ClientOpts {
	if !e.cfg.Camo {
		return nil
	}
	sni := e.cfg.SNI
	if sni == "" {
		sni = "vkvideo.ru"
	}
	return &transport.ClientOpts{SNI: sni, FakeCH: e.cfg.FakeCH, Split: true}
}

// davConn opens one WebDAV mailbox session (client role).
func (e *Engine) davConn() (net.Conn, error) {
	cl, err := webdav.New(e.cfg.DAVURL, e.cfg.DAVUser, e.cfg.DAVPass)
	if err != nil {
		return nil, err
	}
	mailbox := e.cfg.DAVMailbox
	if mailbox == "" {
		mailbox = "qulogi"
	}
	return webdav.OpenPipe(webdav.PipeConfig{
		Client:  cl,
		Mailbox: mailbox,
		Role:    webdav.RoleClient,
		Log:     e.plainLog,
	})
}

// RouteDecision is the per-flow policy used by the VPN transport layer:
// "direct" (straight out), "tunnel" (through the relay) or "drop".
// Without a relay everything is direct; with one, the smart split sends
// whitelisted destinations directly and the rest through the tunnel.
func (e *Engine) RouteDecision(network, addr string) string {
	return e.RouteDomain("", addr)
}

// RouteDomain is the per-flow policy for the sniffing VPN layer: it
// consults the split table with the SNI hostname extracted from the
// ClientHello and falls back to the destination address (an IP) when no
// hostname is known.
func (e *Engine) RouteDomain(sni, addr string) string {
	if !e.proxied() {
		return ViaDirect
	}
	if !e.cfg.SmartSplit {
		return ViaTunnel
	}
	if e.route != nil {
		target := addr
		if sni != "" {
			target = sni
		}
		if e.route.Decide(target) == route.ActionDirect {
			return ViaDirect
		}
	}
	return ViaTunnel
}

// proxied reports whether this engine has an upstream relay at all.
func (e *Engine) proxied() bool {
	return e.cfg.Mode == ModeTunnel ||
		(e.cfg.Mode == ModeVPN && (e.cfg.Server != "" || e.cfg.DAVURL != "" || e.cfg.CDNEdge != "" || e.cfg.BotLPURL != "" || e.cfg.TURNServer != ""))
}

func (e *Engine) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if e.proxied() {
		if e.cfg.SmartSplit && e.RouteDecision(network, addr) == ViaDirect {
			return e.dialDirect(ctx, network, addr)
		}
		return e.dialTunnel(addr)
	}
	return e.dialDirect(ctx, network, addr)
}

// DialVia dials with an explicit routing decision made by the sniffing
// VPN layer ("direct", "tunnel" or "" for the automatic policy).
func (e *Engine) DialVia(ctx context.Context, network, addr, via string) (net.Conn, error) {
	switch via {
	case ViaDirect:
		return e.dialDirect(ctx, network, addr)
	case ViaTunnel:
		return e.dialTunnel(addr)
	default:
		return e.dial(ctx, network, addr)
	}
}

// dialTunnel dials through the relay trying the failover chain: current
// transport first, healthy reserves next, cooled-down ones last. The
// first success becomes the sticky active transport.
func (e *Engine) dialTunnel(addr string) (net.Conn, error) {
	target, err := tunnel.ParseAddress(addr)
	if err != nil {
		return nil, err
	}
	e.monitorOnce.Do(e.startMonitor)
	order := e.candidateOrder()
	if order == nil {
		return nil, errors.New("engine: no transport configured")
	}
	deadline := time.Now().Add(dialBudget)
	var lastErr error
	for _, idx := range order {
		sk, err := e.cands[idx].client.Dial(target)
		if err == nil {
			e.adopt(idx)
			return sk, nil
		}
		lastErr = err
		e.markFailure(idx, err)
		if time.Now().After(deadline) {
			break
		}
	}
	return nil, lastErr
}

// DialPacket opens a UDP tunnel session to addr: the returned conn carries
// framed datagrams (one Write = one datagram). Used by the VPN layer for
// flows the route table sends through the relay — QUIC and friends now
// ride the tunnel instead of being dropped. Storage transports (WebDAV,
// bot long-poll) carry UDP the same way. Without a relay it dials direct.
func (e *Engine) DialPacket(ctx context.Context, addr string) (net.Conn, error) {
	if !e.proxied() {
		return e.dialDirect(ctx, "udp", addr)
	}
	target, err := tunnel.ParseAddress(addr)
	if err != nil {
		return nil, err
	}
	e.monitorOnce.Do(e.startMonitor)
	order := e.candidateOrder()
	if order == nil {
		return nil, errors.New("engine: no transport configured")
	}
	deadline := time.Now().Add(dialBudget)
	var lastErr error
	for _, idx := range order {
		up, err := e.cands[idx].client.DialUDP(target)
		if err == nil {
			e.adopt(idx)
			return up, nil
		}
		lastErr = err
		e.markFailure(idx, err)
		if time.Now().After(deadline) {
			break
		}
	}
	return nil, lastErr
}

// dialDirect opens a socket straight out, applying the platform socket
// protection on Android so the flow is not routed back into the VPN.
func (e *Engine) dialDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if e.cfg.Protect != nil {
		protect := e.cfg.Protect
		d.Control = func(network, address string, c syscall.RawConn) error {
			var perr error
			if cerr := c.Control(func(fd uintptr) {
				if !protect(int32(fd)) {
					perr = errors.New("engine: socket protect failed")
				}
			}); cerr != nil {
				return cerr
			}
			return perr
		}
	}
	return d.DialContext(ctx, network, addr)
}

func (e *Engine) pump(client, upstream net.Conn) error {
	e.conns.Add(1)
	defer e.conns.Add(-1)
	wc := &counting{Conn: client, total: &e.up}
	wu := &counting{Conn: upstream, total: &e.down}
	if e.cfg.Mode == ModeDPI {
		return dpi.Pump(dpi.Strategy{Split: e.cfg.Split, Multi: e.cfg.Multi})(wc, wu)
	}
	return socks5.DefaultPump(wc, wu)
}

func (e *Engine) logf(format string, args ...any) {
	if e.cfg.Log != nil {
		e.cfg.Log(fmt.Sprintf(format, args...))
	}
}

func (e *Engine) plainLog(msg string) {
	if e.cfg.Log != nil {
		e.cfg.Log(msg)
	}
}

type counting struct {
	net.Conn
	total *atomic.Int64
}

func (c *counting) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.total.Add(int64(n))
	}
	return n, err
}
