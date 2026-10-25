package botlp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/mel0k1/qulogi/internal/tunnel"
)

// fakePlatform is an in-memory implementation of the platform contract:
// per-room FIFO queues, long-poll /poll, POST /send.
type fakePlatform struct {
	mu     sync.Mutex
	rooms  map[string]*roomQueue
	token  string
	authed int
}

type roomQueue struct {
	frames [][]byte
	waiter chan struct{} // closed when new frames arrive
}

func newFakePlatform(token string) *fakePlatform {
	return &fakePlatform{rooms: map[string]*roomQueue{}, token: token}
}

func (f *fakePlatform) room(name string) *roomQueue {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.rooms[name]
	if r == nil {
		r = &roomQueue{waiter: make(chan struct{})}
		f.rooms[name] = r
	}
	return r
}

func (f *fakePlatform) push(room string, data []byte) {
	r := f.room(room)
	f.mu.Lock()
	r.frames = append(r.frames, data)
	close(r.waiter)
	r.waiter = make(chan struct{})
	f.mu.Unlock()
}

func (f *fakePlatform) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		var body sendReq
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if body.Token != f.token {
			http.Error(w, "auth", 403)
			return
		}
		data, err := base64.StdEncoding.DecodeString(body.Data)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		f.push(body.Room, data)
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != f.token {
			http.Error(w, "auth", 403)
			return
		}
		room := r.URL.Query().Get("room")
		seq, _ := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
		wait := 2
		if v, err := strconv.Atoi(r.URL.Query().Get("wait")); err == nil && v > 0 && v <= 30 {
			wait = v
		}
		if wait > 30 {
			wait = 30
		}
		deadline := time.After(time.Duration(wait) * time.Second)
		for {
			f.mu.Lock()
			rq := f.rooms[room]
			var (
				frames [][]byte
				newSeq uint64
			)
			if rq != nil {
				for i, fr := range rq.frames {
					if uint64(i) >= seq {
						frames = append(frames, fr)
					}
				}
				newSeq = uint64(len(rq.frames))
			}
			f.mu.Unlock()
			if len(frames) > 0 {
				enc := make([]string, len(frames))
				for i, fr := range frames {
					enc[i] = base64.StdEncoding.EncodeToString(fr)
				}
				w.WriteHeader(200)
				json.NewEncoder(w).Encode(pollResp{Seq: newSeq, Frames: enc})
				return
			}
			select {
			case <-deadline:
				w.WriteHeader(200)
				json.NewEncoder(w).Encode(pollResp{Seq: seq})
				return
			default:
				time.Sleep(20 * time.Millisecond)
			}
		}
	})
	return mux
}

// udpEcho answers every datagram with the same payload.
func udpEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := conn.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr)
}

func TestBotLPEndToEnd(t *testing.T) {
	const psk = "owl-botlp"
	fake := newFakePlatform("bot-token")
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	platform, err := NewPlatform(srv.URL, "bot-token")
	if err != nil {
		t.Fatal(err)
	}

	// The relay listens to the control room; the test waits for it and
	// its session goroutines before returning (no logs after completion).
	ctx, cancel := context.WithCancel(context.Background())
	relayDone := make(chan struct{})
	sessionsDone := make(chan struct{})
	var logMu sync.Mutex
	testOver := false
	safeLog := func(msg string) {
		logMu.Lock()
		defer logMu.Unlock()
		if !testOver {
			t.Log(msg)
		}
	}
	go func() {
		defer close(relayDone)
		_ = ServeRelay(ctx, RelayConfig{
			Platform:     platform,
			Room:         "owl-base",
			PSK:          []byte(psk),
			Idle:         2 * time.Second,
			Log:          safeLog,
			SessionsDone: sessionsDone,
		})
	}()
	t.Cleanup(func() {
		defer func() {
			logMu.Lock()
			testOver = true
			logMu.Unlock()
		}()
		cancel()
		select {
		case <-relayDone:
		case <-time.After(35 * time.Second):
			t.Log("relay goroutine did not stop in time")
		}
		select {
		case <-sessionsDone:
		case <-time.After(35 * time.Second):
			t.Log("session goroutines did not stop in time")
		}
	})

	// TCP echo target.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	// Every tunnel session gets a fresh mailbox pair: the platform rooms
	// are single-use queues, mirroring one session per flow.
	client := &tunnel.Client{PSK: []byte(psk), Conn: func() (net.Conn, error) {
		room, err := NewRoom()
		if err != nil {
			return nil, err
		}
		return OpenPipe(PipeConfig{
			Platform: platform,
			Ctx:      ctx,
			Role:     RoleClient,
			Room:     room,
			Control:  ControlRoom("owl-base"),
			Idle:     60 * time.Second,
			Log:      func(msg string) { t.Log(msg) },
		}, true)
	}}

	t.Run("tcp stream", func(t *testing.T) {
		session, err := client.Dial(tunnel.Address{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port)})
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		if err := session.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
			t.Fatal(err)
		}
		msg := []byte("hello via the bot long-poll")
		for i := 0; i < 2; i++ {
			if _, err := session.Write(msg); err != nil {
				t.Fatalf("write %d: %v", i, err)
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(session, got); err != nil {
				t.Fatalf("read %d: %v", i, err)
			}
			if string(got) != string(msg) {
				t.Fatalf("round %d: %q", i, got)
			}
		}
	})

	t.Run("udp datagrams", func(t *testing.T) {
		echo := udpEcho(t)
		up, err := client.DialUDP(tunnel.Address{Host: "127.0.0.1", Port: uint16(echo.Port)})
		if err != nil {
			t.Fatal(err)
		}
		defer up.Close()
		if err := up.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
			t.Fatal(err)
		}
		msg := []byte("quic-ish datagram")
		if _, err := up.Write(msg); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(up, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != string(msg) {
			t.Fatal("datagram mismatch")
		}
	})
}

func TestParseOpen(t *testing.T) {
	if got := parseOpen([]byte("open:room-ab12")); got != "room-ab12" {
		t.Fatalf("parseOpen: %q", got)
	}
	for _, bad := range []string{"", "hello", "open:", "open:evil/room", "open:not-a-room-prefix", "open:room-with spaces"} {
		if got := parseOpen([]byte(bad)); got != "" {
			t.Fatalf("parseOpen(%q) = %q, want empty", bad, got)
		}
	}
}
