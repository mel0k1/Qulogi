package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mel0k1/qulogi/internal/botlp"
	"github.com/mel0k1/qulogi/internal/tunnel"
	"github.com/mel0k1/qulogi/internal/turnrelay"
)

// startRelay runs a plain tunnel server; returns its address.
func startRelay(t *testing.T, psk string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	// Session handlers may outlive the test; stop logging at cleanup so
	// the testing framework never sees a late write.
	var done atomic.Bool
	srv := &tunnel.Server{Listener: ln, PSK: []byte(psk), Log: func(msg string) {
		if !done.Load() {
			t.Log("relay:", msg)
		}
	}}
	go srv.Serve()
	t.Cleanup(func() {
		done.Store(true)
		ln.Close()
	})
	return ln.Addr().String()
}

// startTurnRelay runs the reference TURN server in front of a target
// address: every Connect allocation dials target.
func startTurnRelay(t *testing.T, target string) string {
	t.Helper()
	var done atomic.Bool
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("turn listen: %v", err)
	}
	srv := &turnrelay.Server{
		Listener: ln,
		Lifetime: 60 * time.Second,
		DialPeer: func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, target, 3*time.Second)
		},
		Log: func(msg string) {
			if !done.Load() {
				t.Log(msg)
			}
		},
	}
	go srv.Serve()
	t.Cleanup(func() {
		done.Store(true)
		srv.Close()
		srv.Wait()
	})
	return ln.Addr().String()
}

// socks5Fetch performs a minimal SOCKS5 CONNECT to listenAddr and returns
// the body of the response from target.
func socks5Fetch(t *testing.T, listenAddr, target string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", listenAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("socks dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	// greeting: no auth
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	host, portS, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portS)
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatalf("connect: %v", err)
	}
	ans := make([]byte, 4)
	if _, err := io.ReadFull(c, ans); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	if ans[1] != 0 {
		t.Fatalf("socks5 error code %d", ans[1])
	}
	rest := make([]byte, 6)
	if ans[3] == 3 {
		rest = rest[:5]
	}
	if _, err := io.ReadFull(c, rest); err != nil {
		t.Fatalf("connect tail: %v", err)
	}
	// HTTP request through the tunnel. The tunnel session does not
	// propagate the target's close, so read until the response headers
	// plus one quiet window are in instead of waiting for EOF.
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("http request: %v", err)
	}
	var raw []byte
	buf := make([]byte, 4096)
	quiet := 0
	for quiet < 2 {
		n, err := c.Read(buf)
		if n > 0 {
			raw = append(raw, buf[:n]...)
			quiet = 0
		}
		if err != nil {
			break // deadline or EOF
		}
		if bytes.Contains(raw, []byte("\r\n\r\n")) {
			quiet++
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		}
	}
	return string(raw)
}

func TestEngineTunnelOverTurn(t *testing.T) {
	psk := "turn-psk"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "QULOGI_VIA_TURN")
	}))
	defer target.Close()

	relay := startRelay(t, psk)
	turnAddr := startTurnRelay(t, relay)

	e := New(Config{
		Mode:       ModeTunnel,
		Listen:     "127.0.0.1:0",
		Server:     relay,
		PSK:        psk,
		TURNServer: turnAddr,
		Log:        func(msg string) { t.Log(msg) },
	})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	body := socks5Fetch(t, e.Status().Listen, strings.TrimPrefix(target.URL, "http://"))
	if !strings.Contains(body, "QULOGI_VIA_TURN") {
		t.Fatalf("unexpected body: %q", body)
	}
	if !e.proxied() {
		t.Fatal("turn transport must count as proxied")
	}
}

func TestEngineTurnNeedsRelayAddress(t *testing.T) {
	e := New(Config{Mode: ModeTunnel, Listen: "127.0.0.1:0", PSK: "x", TURNServer: "127.0.0.1:3478"})
	if err := e.Start(); err == nil {
		t.Fatal("turn without the relay address must fail")
	}
}

// --- fake chat platforms ---

// chatPlatform is an in-memory conversation shared by both sides: posts
// append, long-polls watch by index.
type chatPlatform struct {
	mu     sync.Mutex
	log    []string
	notify chan struct{}
	kind   string // vk | max
}

func newChatPlatform(kind string) *chatPlatform {
	return &chatPlatform{notify: make(chan struct{}, 64), kind: kind}
}

func (p *chatPlatform) post(text string) {
	p.mu.Lock()
	p.log = append(p.log, text)
	p.mu.Unlock()
	select {
	case p.notify <- struct{}{}:
	default:
	}
}

func (p *chatPlatform) snapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.log...)
}

func (p *chatPlatform) VKMethod(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	switch strings.TrimPrefix(r.URL.Path, "/method/") {
	case "messages.send":
		p.post(r.PostFormValue("message"))
		fmt.Fprint(w, `{"response":1}`)
	case "groups.getLongPollServer":
		fmt.Fprintf(w, `{"response":{"server":"http://%s/lp","key":"k","ts":0}}`, r.Host)
	default:
		fmt.Fprint(w, `{"error":{"error_code":1,"error_msg":"unknown"}}`)
	}
}

// longPoll parks until the stream grows beyond the given cursor, then
// answers with every new message in one JSON frame. The empty window is
// short (300ms) to keep the round-trip cost of quiet polls low.
func (p *chatPlatform) longPoll(w http.ResponseWriter, cursor string, wrap func(text string) map[string]any) {
	from, _ := strconv.Atoi(cursor)
	deadline := time.Now().Add(300 * time.Millisecond)
	for {
		snap := p.snapshot()
		if len(snap) > from {
			updates := make([]map[string]any, 0, len(snap)-from)
			for _, text := range snap[from:] {
				updates = append(updates, wrap(text))
			}
			out := map[string]any{"updates": updates}
			if p.kind == "vk" {
				out["ts"] = len(snap)
			} else {
				out["marker"] = strconv.Itoa(len(snap))
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		select {
		case <-p.notify:
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			out := map[string]any{"updates": []map[string]any{}}
			if p.kind == "vk" {
				out["ts"] = from
			} else {
				out["marker"] = strconv.Itoa(from)
			}
			_ = json.NewEncoder(w).Encode(out)
			return
		}
	}
}

func startChatAPI(t *testing.T, kind string) string {
	t.Helper()
	p := newChatPlatform(kind)
	mux := http.NewServeMux()
	if kind == "vk" {
		mux.HandleFunc("/method/messages.send", p.VKMethod)
		mux.HandleFunc("/method/groups.getLongPollServer", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"response":{"server":"http://%s/lp","key":"k","ts":0}}`, r.Host)
		})
		mux.HandleFunc("/lp", func(w http.ResponseWriter, r *http.Request) {
			p.longPoll(w, r.FormValue("ts"), func(text string) map[string]any {
				return map[string]any{
					"type": "message_new",
					"object": map[string]any{
						"message": map[string]any{"text": text},
					},
				}
			})
		})
	} else {
		mux.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Text string `json:"text"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			p.post(body.Text)
			fmt.Fprint(w, `{"message":{}}`)
		})
		mux.HandleFunc("/updates", func(w http.ResponseWriter, r *http.Request) {
			p.longPoll(w, r.FormValue("marker"), func(text string) map[string]any {
				return map[string]any{
					"update_type": "message_created",
					"payload": map[string]any{
						"message": map[string]any{
							"body": map[string]any{"text": text},
						},
					},
				}
			})
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestEngineTunnelOverChatBridges(t *testing.T) {
	for _, kind := range []string{"vk", "max"} {
		t.Run(kind, func(t *testing.T) {
			psk := "chat-psk"
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "QULOGI_VIA_CHAT")
			}))
			defer target.Close()

			apiURL := startChatAPI(t, kind)
			// The adapters default to the real platform roots; the fake
			// mimics the same paths (VK methods live under /method/).
			fakeBase := apiURL
			if kind == "vk" {
				fakeBase = apiURL + "/method/"
			}

			// Relay side: the control loop with the same fake platform.
			api, _, err := botlp.BuildAPI(kind, fakeBase, "tok-relay", "base", "42")
			if err != nil {
				t.Fatalf("build relay api: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			relayErr := make(chan error, 1)
			go func() {
				relayErr <- botlp.ServeRelay(ctx, botlp.RelayConfig{
					Platform: api,
					Room:     "base",
					PSK:      []byte(psk),
					Log:      func(msg string) { t.Log(msg) },
				})
			}()

			e := New(Config{
				Mode:       ModeTunnel,
				Listen:     "127.0.0.1:0",
				PSK:        psk,
				Log:        func(msg string) { t.Log(msg) },
				BotLPURL:   fakeBase,
				BotLPToken: "tok-client",
				BotLPKind:  kind,
				BotLPChat:  "42",
				BotLPRoom:  "base",
			})
			if err := e.Start(); err != nil {
				t.Fatalf("start: %v", err)
			}
			defer e.Stop()

			body := socks5Fetch(t, e.Status().Listen, strings.TrimPrefix(target.URL, "http://"))
			if !strings.Contains(body, "QULOGI_VIA_CHAT") {
				t.Fatalf("unexpected body: %q", body)
			}
			cancel()
			select {
			case <-relayErr:
			case <-time.After(2 * time.Second):
				t.Log("relay loop still draining")
			}
		})
	}
}

func TestBuildAPIKinds(t *testing.T) {
	if _, _, err := botlp.BuildAPI("ldap", "http://x", "t", "r", "1"); err == nil {
		t.Fatal("unknown kind must fail")
	}
	if _, _, err := botlp.BuildAPI("", "", "t", "r", "1"); err == nil {
		t.Fatal("generic without url must fail")
	}
	if _, chunk, err := botlp.BuildAPI("vk", "", "t", "r", "1"); err != nil || chunk != 2800 {
		t.Fatalf("vk build: chunk=%d err=%v", chunk, err)
	}
	if _, chunk, err := botlp.BuildAPI("max", "", "t", "r", "1"); err != nil || chunk != 2800 {
		t.Fatalf("max build: chunk=%d err=%v", chunk, err)
	}
	if _, _, err := botlp.BuildAPI("vk", "", "t", "r", "not-a-peer"); err == nil {
		t.Fatal("vk with a bad peer id must fail")
	}
}
