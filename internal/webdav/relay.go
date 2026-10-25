package webdav

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mel0k1/qulogi/internal/tunnel"
)

// RelayConfig wires the relay side of the storage transport.
type RelayConfig struct {
	Client *Client
	// Mailbox is the base directory to watch: every "s-<hex>" collection
	// that appears there is treated as an incoming tunnel session.
	Mailbox string
	PSK     []byte
	// Poll is the base directory listing interval (default 2s).
	Poll time.Duration
	Log  func(string)
}

// ServeRelay watches the mailbox base directory and serves every incoming
// session with tunnel.AcceptSession until ctx is cancelled. One relay
// process per mailbox base: sessions are claimed by an in-memory set, so
// two relays on the same mailbox would fight over sessions.
func ServeRelay(ctx context.Context, cfg RelayConfig) error {
	if cfg.Client == nil {
		return fmt.Errorf("webdav: client required")
	}
	if cfg.Poll == 0 {
		cfg.Poll = defaultPoll
	}
	base := strings.Trim(cfg.Mailbox, "/")
	if base == "" {
		return fmt.Errorf("webdav: mailbox required")
	}
	logf := func(format string, args ...any) {
		if cfg.Log != nil {
			cfg.Log(fmt.Sprintf(format, args...))
		}
	}
	// Make sure the base mailbox exists: watching a missing collection
	// would otherwise log a 404 on every poll.
	if err := cfg.Client.MkdirAll(ctx, base); err != nil {
		return fmt.Errorf("webdav: create %s: %w", base, err)
	}
	logf("webdav: relay watching %s", base)

	seen := map[string]bool{}
	for {
		names, err := cfg.Client.List(ctx, base)
		if err != nil && !errors.Is(err, context.Canceled) {
			logf("webdav: watch %s: %v", base, err)
		}
		for _, n := range names {
			if !isSessionDir(n) || seen[n] {
				continue
			}
			seen[n] = true
			session := base + "/" + strings.TrimSuffix(n, "/")
			go serveSession(cfg, session, logf)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cfg.Poll):
		}
	}
}

func serveSession(cfg RelayConfig, session string, logf func(string, ...any)) {
	logf("webdav: session %s: incoming", session)
	pipe, err := OpenPipe(PipeConfig{
		Client:  cfg.Client,
		Mailbox: strings.Trim(cfg.Mailbox, "/"),
		Session: strings.TrimPrefix(session, strings.Trim(cfg.Mailbox, "/")+"/"),
		Role:    RoleRelay,
		Log:     func(msg string) { logf("%s", msg) },
	})
	if err != nil {
		logf("webdav: session %s: %v", session, err)
		return
	}
	// Zombie sessions die via the pipe idle timeout (10 min for the
	// relay role); active sessions keep refreshing it.
	if err := tunnel.AcceptSession(pipe, cfg.PSK, func(msg string) { logf("%s %s", session, msg) }); err != nil {
		logf("webdav: session %s: %v", session, err)
	}
	_ = pipe.Cleanup()
	logf("webdav: session %s: closed", session)
}

// isSessionDir reports whether a listed name looks like a client session
// collection ("s-<12 hex>" with an optional trailing slash).
func isSessionDir(name string) bool {
	name = strings.TrimSuffix(name, "/")
	if len(name) != sessionNameLen || !strings.HasPrefix(name, sessionPrefix) {
		return false
	}
	for _, c := range name[len(sessionPrefix):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
