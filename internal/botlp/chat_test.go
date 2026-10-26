package botlp

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mel0k1/qulogi/internal/tunnel"
)

// memChat is an in-memory conversation: posts append to a shared log,
// every view long-polls it with its own cursor.
type memChat struct {
	mu     sync.Mutex
	log    []string
	notify chan struct{}
}

func newMemChat() *memChat { return &memChat{notify: make(chan struct{}, 64)} }

func (m *memChat) post(text string) {
	m.mu.Lock()
	m.log = append(m.log, text)
	n := len(m.log)
	m.mu.Unlock()
	for i := 0; i < n; i++ {
		select {
		case m.notify <- struct{}{}:
		default:
		}
	}
}

func (m *memChat) since(from uint64) ([]string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if uint64(len(m.log)) > from {
		out := append([]string(nil), m.log[from:]...)
		return out, true
	}
	return nil, false
}

// view is one poller's cursor over the shared conversation.
type view struct {
	m      *memChat
	mu     sync.Mutex
	cursor uint64
}

func (v *view) SendText(ctx context.Context, text string) error {
	v.m.post(text)
	return nil
}

func (v *view) PollTexts(ctx context.Context, wait time.Duration) (uint64, []string, error) {
	v.mu.Lock()
	from := v.cursor
	v.mu.Unlock()
	deadline := time.Now().Add(wait)
	for {
		texts, ok := v.m.since(from)
		if ok {
			v.mu.Lock()
			v.cursor = from + uint64(len(texts))
			cur := v.cursor
			v.mu.Unlock()
			return cur, texts, nil
		}
		select {
		case <-v.m.notify:
		case <-ctx.Done():
			return from, nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return from, nil, nil
		}
	}
}

func TestChatBridgeTunnelEndToEnd(t *testing.T) {
	psk := "chat-e2e"
	shared := newMemChat()

	// Echo target behind the relay.
	echo := make(chan []byte, 16)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				echo <- buf[:n]
				c.Write(buf[:n])
			}()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sessionsDone := make(chan struct{})
	relayErr := make(chan error, 1)
	relayBridge := NewChatBridge(&view{m: shared})
	relayBridge.Wait = 25 * time.Second
	relayBridge.Log = func(msg string) { t.Log("relay-bridge:", msg) }
	go func() {
		relayErr <- ServeRelay(ctx, RelayConfig{
			Platform:     relayBridge,
			Room:         "base",
			PSK:          []byte(psk),
			Log:          func(msg string) { t.Log("relay:", msg) },
			SessionsDone: sessionsDone,
		})
	}()

	cl := &tunnel.Client{
		PSK: []byte(psk),
		Conn: func() (net.Conn, error) {
			room, err := NewRoom()
			if err != nil {
				return nil, err
			}
			clientBridge := NewChatBridge(&view{m: shared})
			clientBridge.Wait = 25 * time.Second
			clientBridge.Log = func(msg string) { t.Log("client-bridge:", msg) }
			return OpenPipe(PipeConfig{
				Platform: clientBridge,
				Role:     RoleClient,
				Room:     room,
				Control:  ControlRoom("base"),
				Chunk:    chatFrameLimit,
				Log:      func(msg string) { t.Log("client-pipe:", msg) },
			}, true)
		},
	}
	addr, err := tunnel.ParseAddress(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := cl.Dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("ping-over-chat-bridge")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: %q", got)
	}
	cancel()
	<-relayErr
	<-sessionsDone
}
