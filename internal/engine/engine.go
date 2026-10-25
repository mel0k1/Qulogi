package engine

import (
        "context"
        "errors"
        "fmt"
        "net"
        "sync"
        "sync/atomic"
        "time"

        "github.com/mel0k1/qulogi/internal/dpi"
        "github.com/mel0k1/qulogi/internal/socks5"
        "github.com/mel0k1/qulogi/internal/tunnel"
)

type Mode string

const (
        ModeTunnel Mode = "tunnel"
        ModeDPI    Mode = "dpi"
)

type Config struct {
        Mode   Mode         `json:"mode"`
        Listen string       `json:"listen"`
        Server string       `json:"server,omitempty"`
        PSK    string       `json:"psk,omitempty"`
        Split  int          `json:"split,omitempty"`
        Log    func(string) `json:"-"`
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
}

type Engine struct {
        cfg Config

        mu       sync.Mutex
        listener net.Listener
        client   *tunnel.Client
        running  bool
        started  time.Time

        conns atomic.Int64
        up    atomic.Int64
        down  atomic.Int64
}

func New(cfg Config) *Engine {
        if cfg.Listen == "" {
                cfg.Listen = "127.0.0.1:1080"
        }
        if cfg.Mode == "" {
                cfg.Mode = ModeDPI
        }
        return &Engine{cfg: cfg}
}

func (e *Engine) Start() error {
        e.mu.Lock()
        defer e.mu.Unlock()
        if e.running {
                return errors.New("engine: already running")
        }
        switch e.cfg.Mode {
        case ModeTunnel:
                if e.cfg.Server == "" {
                        return errors.New("engine: server required in tunnel mode")
                }
                if e.cfg.PSK == "" {
                        return errors.New("engine: psk required in tunnel mode")
                }
                e.client = &tunnel.Client{Server: e.cfg.Server, PSK: []byte(e.cfg.PSK)}
        case ModeDPI:
        default:
                return fmt.Errorf("engine: unknown mode %q", e.cfg.Mode)
        }
        ln, err := net.Listen("tcp", e.cfg.Listen)
        if err != nil {
                return err
        }
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
        e.mu.Lock()
        ln := e.listener
        e.listener = nil
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
        e.mu.Unlock()
        st := Status{
                Running:     running,
                Mode:        string(e.cfg.Mode),
                Listen:      e.cfg.Listen,
                Server:      e.cfg.Server,
                Connections: e.conns.Load(),
                BytesUp:     e.up.Load(),
                BytesDown:   e.down.Load(),
        }
        if running {
                st.Uptime = int64(time.Since(started).Seconds())
        }
        return st
}

func (e *Engine) dial(ctx context.Context, network, addr string) (net.Conn, error) {
        if e.cfg.Mode == ModeTunnel {
                target, err := tunnel.ParseAddress(addr)
                if err != nil {
                        return nil, err
                }
                return e.client.Dial(target)
        }
        d := &net.Dialer{Timeout: 10 * time.Second}
        return d.DialContext(ctx, network, addr)
}

func (e *Engine) pump(client, upstream net.Conn) error {
        e.conns.Add(1)
        defer e.conns.Add(-1)
        wc := &counting{Conn: client, total: &e.up}
        wu := &counting{Conn: upstream, total: &e.down}
        if e.cfg.Mode == ModeDPI {
                return dpi.Pump(e.cfg.Split)(wc, wu)
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
