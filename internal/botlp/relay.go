package botlp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mel0k1/qulogi/internal/tunnel"
)

// RelayConfig wires the relay side of the bot-longpoll transport.
type RelayConfig struct {
	// Platform is the API adapter (generic contract or a chat bridge).
	Platform API
	// Room is the operator's base room; the control room <Room>-ctl
	// carries session advertisements ("open:<session-room>").
	Room string
	PSK  []byte
	Idle time.Duration
	// Idle bounds quiet sessions (default 10 min; useful to shrink in
	// tests).
	// Log receives relay events.
	Log func(string)
	// SessionsDone, when set, is closed after ctx cancellation once every
	// session goroutine has exited.
	SessionsDone chan struct{}
}

// ServeRelay long-polls the control room and serves every announced
// session with tunnel.AcceptSession until ctx is cancelled. Frames of each
// session ride their own room; the relay polls one session room per live
// tunnel session.
func ServeRelay(ctx context.Context, cfg RelayConfig) error {
	if cfg.Platform == nil || strings.TrimSpace(cfg.Room) == "" {
		return errors.New("botlp: platform and room are required")
	}
	logf := func(format string, args ...any) {
		if cfg.Log != nil {
			cfg.Log(fmt.Sprintf(format, args...))
		}
	}
	ctl := ControlRoom(cfg.Room)
	logf("botlp: relay listening on control room %s", ctl)

	var (
		mu   sync.Mutex
		sess = map[string]bool{} // advertised rooms already served
		seq  uint64
	)
	var wg sync.WaitGroup
	if cfg.SessionsDone != nil {
		defer close(cfg.SessionsDone)
		defer wg.Wait()
	}
	for {
		newSeq, frames, err := cfg.Platform.Poll(ctx, ctl, seq)
		if err != nil {
			if errors.Is(err, context.Canceled) || ctx.Err() != nil {
				return ctx.Err()
			}
			// Flaky polls must not kill the listener: back off briefly.
			logf("botlp: control poll: %v", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
			continue
		}
		seq = newSeq
		for _, f := range frames {
			room := parseOpen(f)
			if room == "" {
				continue
			}
			mu.Lock()
			fresh := !sess[room]
			sess[room] = true
			mu.Unlock()
			if !fresh {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				serveSession(ctx, cfg, room, logf)
			}()
		}
	}
}

// parseOpen recognises "open:<room>" control frames.
func parseOpen(frame []byte) string {
	s := strings.TrimSpace(string(frame))
	if !strings.HasPrefix(s, "open:") {
		return ""
	}
	room := strings.TrimPrefix(s, "open:")
	if !strings.HasPrefix(room, sessionPrefix) || len(room) > 64 ||
		strings.ContainsAny(room, "/ \t\r\n") {
		return ""
	}
	return room
}

func serveSession(ctx context.Context, cfg RelayConfig, room string, logf func(string, ...any)) {
	logf("botlp: session %s: incoming", room)
	pipe, err := OpenPipe(PipeConfig{
		Platform: cfg.Platform,
		Role:     RoleRelay,
		Room:     room,
		Ctx:      ctx,
		Idle:     cfg.Idle,
		Log:      func(msg string) { logf("%s", msg) },
	}, false)
	if err != nil {
		logf("botlp: session %s: %v", room, err)
		return
	}
	defer pipe.Close()
	// Quiet sessions are reaped by the pipe idle timeout (10 min for the
	// relay role); active sessions keep refreshing it.
	if err := tunnel.AcceptSession(pipe, cfg.PSK, func(msg string) { logf("%s %s", room, msg) }); err != nil {
		logf("botlp: session %s: %v", room, err)
	}
	logf("botlp: session %s: closed", room)
}
