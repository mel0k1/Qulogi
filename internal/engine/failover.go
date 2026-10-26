package engine

// Auto-failover: reserve transports probed in the background, switched to
// on degradation and back when the best one recovers. The primary
// transport stays in the flat Config fields; Fallbacks lists the reserves.

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/mel0k1/qulogi/internal/botlp"
	"github.com/mel0k1/qulogi/internal/cdnfront"
	"github.com/mel0k1/qulogi/internal/tunnel"
	"github.com/mel0k1/qulogi/internal/turnrelay"
	"github.com/mel0k1/qulogi/internal/webdav"
)

// TransportSpec describes one reserve transport in the failover chain.
type TransportSpec struct {
	// Kind: "tcp", "cdn", "botlp", "dav" or "turn".
	Kind string `json:"kind"`
	// tcp: relay host:port. cdn: edge host:port. turn: TURN endpoint.
	Server string `json:"server,omitempty"`
	// cdn: TLS SNI (default Host). turn: relay peer address.
	SNI  string `json:"sni,omitempty"`
	Host string `json:"host,omitempty"`
	// cdn: RFC 6455 WebSocket upgrade (real CDN networks).
	WS bool `json:"ws,omitempty"`
	// PSK overrides the engine PSK for this candidate.
	PSK string `json:"psk,omitempty"`
	// botlp/dav endpoint URL.
	URL string `json:"url,omitempty"`
	// botlp: platform token and operator base room; Platform: "vk"/"max";
	// Chat: peer id. dav: mailbox directory.
	Token    string `json:"token,omitempty"`
	Room     string `json:"room,omitempty"`
	Platform string `json:"platform,omitempty"`
	Chat     string `json:"chat,omitempty"`
	Mailbox  string `json:"mailbox,omitempty"`
	// dav/turn credentials.
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
}

const (
	dialBudget     = 25 * time.Second
	probeTimeout   = 6 * time.Second
	probeInterval  = 15 * time.Second
	probeSlowRTT   = 3 * time.Second
	probeTargetStr = "192.0.2.1:9" // TEST-NET-1: handshake round-trip only
	coolDown       = 30 * time.Second
	failThreshold  = 2
)

var probeTarget = mustAddress(probeTargetStr)

func mustAddress(s string) tunnel.Address {
	a, err := tunnel.ParseAddress(s)
	if err != nil {
		panic("engine: bad probe target: " + err.Error())
	}
	return a
}

type candidate struct {
	name   string
	probe  bool // cheap enough for proactive health probes
	client *tunnel.Client
}

func (e *Engine) buildCandidates() []candidate {
	var out []candidate
	if c, ok := e.primaryCandidate(); ok {
		out = append(out, c)
	}
	for _, spec := range e.cfg.Fallbacks {
		c, err := e.fallbackCandidate(spec)
		if err != nil {
			continue // validated in Start; skip garbage defensively
		}
		out = append(out, c)
	}
	return out
}

// primaryCandidate mirrors the flat config fields (cdn > botlp > dav >
// turn > tcp priority kept from earlier releases).
func (e *Engine) primaryCandidate() (candidate, bool) {
	c := candidate{probe: true}
	psk := []byte(e.cfg.PSK)
	switch {
	case e.cfg.CDNEdge != "":
		edge, host, sni := e.cfg.CDNEdge, e.cfg.CDNHost, e.cfg.CDNSNI
		ws := e.cfg.CDNWS
		c.name = "cdn:" + edge
		c.client = &tunnel.Client{PSK: psk, Conn: func() (net.Conn, error) {
			if ws {
				return cdnfront.WSFront{EdgeAddr: edge, EdgeSNI: sni, Host: host}.Dial()
			}
			return cdnfront.Front{EdgeAddr: edge, EdgeSNI: sni, Host: host}.Dial()
		}}
	case e.cfg.BotLPURL != "":
		api, chunk, err := botlp.BuildAPI(e.cfg.BotLPKind, e.cfg.BotLPURL, e.cfg.BotLPToken, e.cfg.BotLPRoom, e.cfg.BotLPChat)
		if err != nil {
			return candidate{}, false
		}
		c.name = "botlp:" + e.cfg.BotLPRoom
		c.probe = false
		c.client = &tunnel.Client{PSK: psk, Conn: func() (net.Conn, error) {
			return e.botlpConn(api, chunk)
		}}
	case e.cfg.DAVURL != "":
		c.name = "dav:" + e.cfg.DAVURL
		c.probe = false
		c.client = &tunnel.Client{PSK: psk, Conn: e.davConn}
	case e.cfg.TURNServer != "":
		turnAddr, user, pass, peer := e.cfg.TURNServer, e.cfg.TURNUser, e.cfg.TURNPass, e.cfg.Server
		c.name = "turn:" + turnAddr
		c.client = &tunnel.Client{PSK: psk, Conn: func() (net.Conn, error) {
			return (&turnrelay.Client{Server: turnAddr, User: user, Pass: pass, Log: e.plainLog}).Dial(peer)
		}}
	case e.cfg.Server != "":
		c.name = "tcp:" + e.cfg.Server
		c.client = &tunnel.Client{Server: e.cfg.Server, PSK: psk, Camo: e.camoOpts()}
	default:
		return candidate{}, false
	}
	return c, true
}

func (e *Engine) fallbackCandidate(spec TransportSpec) (candidate, error) {
	psk := []byte(e.cfg.PSK)
	if spec.PSK != "" {
		psk = []byte(spec.PSK)
	}
	c := candidate{probe: true}
	switch spec.Kind {
	case "tcp":
		if spec.Server == "" {
			return candidate{}, errors.New("tcp fallback needs server")
		}
		c.name = "tcp:" + spec.Server
		c.client = &tunnel.Client{Server: spec.Server, PSK: psk, Camo: e.camoOpts()}
	case "cdn":
		if spec.Host == "" {
			return candidate{}, errors.New("cdn fallback needs host")
		}
		c.name = "cdn:" + spec.Host
		ws := spec.WS
		sni := spec.SNI
		c.client = &tunnel.Client{PSK: psk, Conn: func() (net.Conn, error) {
			if ws {
				return cdnfront.WSFront{EdgeAddr: spec.Server, EdgeSNI: sni, Host: spec.Host}.Dial()
			}
			return cdnfront.Front{EdgeAddr: spec.Server, EdgeSNI: sni, Host: spec.Host}.Dial()
		}}
	case "botlp":
		api, chunk, err := botlp.BuildAPI(spec.Platform, spec.URL, spec.Token, spec.Room, spec.Chat)
		if err != nil {
			return candidate{}, err
		}
		c.name = "botlp:" + spec.Room
		c.probe = false
		c.client = &tunnel.Client{PSK: psk, Conn: func() (net.Conn, error) {
			return e.botlpConn(api, chunk)
		}}
	case "dav":
		if spec.URL == "" {
			return candidate{}, errors.New("dav fallback needs url")
		}
		c.name = "dav:" + spec.URL
		c.probe = false
		cl, err := webdav.New(spec.URL, spec.User, spec.Pass)
		if err != nil {
			return candidate{}, err
		}
		mailbox := spec.Mailbox
		if mailbox == "" {
			mailbox = "qulogi"
		}
		c.client = &tunnel.Client{PSK: psk, Conn: func() (net.Conn, error) {
			return webdav.OpenPipe(webdav.PipeConfig{Client: cl, Mailbox: mailbox, Role: webdav.RoleClient, Log: e.plainLog})
		}}
	case "turn":
		if spec.Server == "" || spec.Host == "" {
			return candidate{}, errors.New("turn fallback needs server and host")
		}
		c.name = "turn:" + spec.Server
		turnAddr, user, pass, peer := spec.Server, spec.User, spec.Pass, spec.Host
		c.client = &tunnel.Client{PSK: psk, Conn: func() (net.Conn, error) {
			return (&turnrelay.Client{Server: turnAddr, User: user, Pass: pass, Log: e.plainLog}).Dial(peer)
		}}
	default:
		return candidate{}, fmt.Errorf("unknown fallback kind %q", spec.Kind)
	}
	return c, nil
}

// botlpConn opens one client-role chat pipe.
func (e *Engine) botlpConn(api botlp.API, chunk int) (net.Conn, error) {
	room, err := botlp.NewRoom()
	if err != nil {
		return nil, err
	}
	return botlp.OpenPipe(botlp.PipeConfig{
		Platform: api,
		Role:     botlp.RoleClient,
		Room:     room,
		Control:  botlp.ControlRoom(e.cfg.BotLPRoom),
		Chunk:    chunk,
		Log:      e.plainLog,
	}, true)
}

// current returns the active candidate index.
func (e *Engine) current() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cur >= len(e.cands) {
		return 0
	}
	return e.cur
}

// candidateOrder lists candidates to try: current first, then healthy
// reserves by priority, cooled-down ones last.
func (e *Engine) candidateOrder() []int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := len(e.cands)
	if n == 0 {
		return nil
	}
	now := time.Now()
	order := []int{e.cur}
	var rest, cooled []int
	for i := 0; i < n; i++ {
		if i == e.cur {
			continue
		}
		if e.cool[i].After(now) {
			cooled = append(cooled, i)
		} else {
			rest = append(rest, i)
		}
	}
	return append(order, append(rest, cooled...)...)
}

func (e *Engine) adopt(idx int) {
	e.mu.Lock()
	e.fails[idx] = 0
	prev := e.cur
	e.cur = idx
	e.mu.Unlock()
	if prev != idx {
		e.failovers.Add(1)
		e.logf("failover: %s -> %s", e.cands[prev].name, e.cands[idx].name)
	}
}

func (e *Engine) markFailure(idx int, err error) {
	e.mu.Lock()
	e.fails[idx]++
	n := e.fails[idx]
	armed := false
	if n >= failThreshold && !e.cool[idx].After(time.Now()) {
		e.cool[idx] = time.Now().Add(coolDown)
		armed = true
	}
	e.mu.Unlock()
	if armed {
		e.logf("transport %s degraded (%d failures: %v)", e.cands[idx].name, n, err)
	}
}

// startMonitor launches the degradation monitor once. Called lazily from
// the dial path so both tunnel and VPN modes are covered.
func (e *Engine) startMonitor() {
	if e.cfg.NoFailover || len(e.cands) < 2 {
		return
	}
	interval := time.Duration(e.cfg.FailoverProbeSecs) * time.Second
	if interval <= 0 {
		interval = probeInterval
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-e.stopMon:
				return
			case <-t.C:
				e.probeCycle()
			}
		}
	}()
	e.logf("failover monitor on (%d transports, probe every %s)", len(e.cands), interval)
}

// probeCycle checks the active transport and, when away from the best
// one, tries to move back.
func (e *Engine) probeCycle() {
	cur := e.current()
	if e.cands[cur].probe {
		rtt, err := e.probe(cur)
		if err != nil {
			e.markFailure(cur, err)
			e.failIfDegraded(cur)
			return
		}
		e.mu.Lock()
		e.fails[cur] = 0
		e.mu.Unlock()
		if rtt > probeSlowRTT {
			e.logf("transport %s slow: rtt %s", e.cands[cur].name, rtt.Round(time.Millisecond))
		}
	}
	if cur != 0 {
		e.tryRecover(cur)
	}
}

// probe opens a throwaway session through the candidate: a completed
// handshake is a live path; the throwaway target fails on the relay side.
func (e *Engine) probe(idx int) (time.Duration, error) {
	start := time.Now()
	conn, err := e.cands[idx].client.Dial(probeTarget)
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start), nil
}

// failIfDegraded moves to the next healthy candidate when the current
// one is cooled down.
func (e *Engine) failIfDegraded(cur int) {
	e.mu.Lock()
	cooled := e.cool[cur].After(time.Now())
	e.mu.Unlock()
	if !cooled {
		return
	}
	for _, idx := range e.candidateOrder() {
		if idx == cur {
			continue
		}
		e.mu.Lock()
		free := !e.cool[idx].After(time.Now())
		e.mu.Unlock()
		if !free {
			continue
		}
		if _, err := e.probe(idx); err != nil {
			e.markFailure(idx, err)
			continue
		}
		e.adopt(idx)
		return
	}
	e.logf("failover: no healthy reserve, staying on %s", e.cands[cur].name)
}

// tryRecover moves back to the highest-priority healthy candidate.
func (e *Engine) tryRecover(cur int) {
	for idx := 0; idx < cur; idx++ {
		e.mu.Lock()
		free := !e.cool[idx].After(time.Now())
		e.mu.Unlock()
		if !free {
			continue
		}
		if _, err := e.probe(idx); err != nil {
			continue
		}
		e.adopt(idx)
		return
	}
}

// validateFallbacks checks the reserve specs at Start.
func (e *Engine) validateFallbacks() error {
	for _, spec := range e.cfg.Fallbacks {
		switch spec.Kind {
		case "tcp":
			if spec.Server == "" {
				return errors.New("fallback tcp: server required")
			}
		case "cdn":
			if spec.Host == "" {
				return errors.New("fallback cdn: host required")
			}
		case "botlp":
			if _, _, err := botlp.BuildAPI(spec.Platform, spec.URL, spec.Token, spec.Room, spec.Chat); err != nil {
				return fmt.Errorf("fallback botlp: %w", err)
			}
		case "dav":
			if spec.URL == "" {
				return errors.New("fallback dav: url required")
			}
		case "turn":
			if spec.Server == "" || spec.Host == "" {
				return errors.New("fallback turn: server and host required")
			}
		default:
			return fmt.Errorf("fallback: unknown kind %q", spec.Kind)
		}
	}
	return nil
}

// TransportName reports the active transport for Status.
func (e *Engine) TransportName() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cur < len(e.cands) {
		return e.cands[e.cur].name
	}
	return ""
}
