package webdav

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// davTree is a minimal in-memory WebDAV server: PUT/GET/MKCOL/DELETE plus
// a Depth-1 PROPFIND. Good enough to exercise the client and the mailbox
// transport end to end.
type davTree struct {
	mu   sync.Mutex
	dirs map[string]bool
	objs map[string][]byte
}

func newDavTree() *davTree {
	return &davTree{dirs: map[string]bool{"/": true}, objs: map[string][]byte{}}
}

func (t *davTree) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if !strings.HasSuffix(p, "/") && t.isDir(p) {
			p += "/"
		}
		switch r.Method {
		case "MKCOL":
			t.mu.Lock()
			t.dirs[strings.TrimSuffix(p, "/")] = true
			t.mu.Unlock()
			w.WriteHeader(201)
		case "PUT":
			body, _ := io.ReadAll(r.Body)
			t.mu.Lock()
			t.objs[strings.TrimSuffix(p, "/")] = body
			t.mu.Unlock()
			w.WriteHeader(201)
		case "GET":
			t.mu.Lock()
			body, ok := t.objs[strings.TrimSuffix(p, "/")]
			t.mu.Unlock()
			if !ok {
				http.Error(w, "not found", 404)
				return
			}
			w.Write(body)
		case "DELETE":
			t.mu.Lock()
			delete(t.objs, strings.TrimSuffix(p, "/"))
			delete(t.dirs, strings.TrimSuffix(p, "/"))
			t.mu.Unlock()
			w.WriteHeader(204)
		case "PROPFIND":
			var sb strings.Builder
			sb.WriteString(`<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">`)
			for _, child := range t.children(p) {
				sb.WriteString(`<d:response><d:href>` + child + `</d:href></d:response>`)
			}
			sb.WriteString(`</d:multistatus>`)
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(207)
			w.Write([]byte(sb.String()))
		default:
			http.Error(w, "unsupported", 405)
		}
	})
}

func (t *davTree) isDir(p string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dirs[strings.TrimSuffix(p, "/")]
}

// children lists the direct children of p (Depth 1) as hrefs.
func (t *davTree) children(p string) []string {
	p = strings.TrimSuffix(p, "/")
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for d := range t.dirs {
		if d != p && strings.HasPrefix(d, p+"/") && !strings.Contains(strings.TrimPrefix(d, p+"/"), "/") {
			out = append(out, d+"/")
		}
	}
	for o := range t.objs {
		if strings.HasPrefix(o, p+"/") && !strings.Contains(strings.TrimPrefix(o, p+"/"), "/") {
			out = append(out, o)
		}
	}
	sort.Strings(out)
	return out
}

// davTestServer boots the fake cloud and returns a client bound to it.
func davTestServer(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewServer(newDavTree().handler())
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "owl", "h00t")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClientCRUD(t *testing.T) {
	c := davTestServer(t)
	ctx := context.Background()

	if err := c.MkdirAll(ctx, "qulogi/box"); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, "qulogi/box/up/000000000001.chunk", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	got, err := c.Get(ctx, "qulogi/box/up/000000000001.chunk")
	if err != nil || string(got) != "hello" {
		t.Fatalf("get: %q %v", got, err)
	}
	names, err := c.List(ctx, "qulogi/box/up")
	if err != nil || len(names) != 1 || names[0] != "000000000001.chunk" {
		t.Fatalf("list: %v %v", names, err)
	}
	if err := c.Delete(ctx, "qulogi/box/up/000000000001.chunk"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "qulogi/box/up/000000000001.chunk"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestClientListEscaped(t *testing.T) {
	c := davTestServer(t)
	ctx := context.Background()
	if err := c.MkdirAll(ctx, "box"); err != nil {
		t.Fatal(err)
	}
	// Names with characters servers usually escape in hrefs.
	for _, name := range []string{"a b.chunk", "тюлень.chunk"} {
		if err := c.Put(ctx, "box/"+name, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	names, err := c.List(ctx, "box")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("list: %v", names)
	}
}

func TestPipeStream(t *testing.T) {
	c := davTestServer(t)

	sender, err := OpenPipe(PipeConfig{
		Client: c, Mailbox: "box", Role: RoleClient,
		Chunk: 8 << 10, Poll: 50 * time.Millisecond, Idle: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := OpenPipe(PipeConfig{
		Client: c, Mailbox: "box", Session: sender.SessionName(),
		Role: RoleRelay, Chunk: 8 << 10, Poll: 50 * time.Millisecond, Idle: -1,
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := make([]byte, 40<<10)
	for i := range payload {
		payload[i] = byte(i)
	}
	go func() {
		if _, err := sender.Write(payload); err != nil {
			t.Errorf("write: %v", err)
		}
		sender.Close()
	}()

	got := make([]byte, 0, len(payload))
	buf := make([]byte, 3000)
	for len(got) < len(payload) {
		n, err := receiver.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			t.Fatalf("read after %d bytes: %v", len(got), err)
		}
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("byte %d: got %d want %d", i, got[i], payload[i])
		}
	}
}

func TestPipeBidirectional(t *testing.T) {
	c := davTestServer(t)

	clientEnd, err := OpenPipe(PipeConfig{
		Client: c, Mailbox: "box", Role: RoleClient,
		Chunk: 16 << 10, Poll: 25 * time.Millisecond, Idle: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	relayEnd, err := OpenPipe(PipeConfig{
		Client: c, Mailbox: "box", Session: clientEnd.SessionName(),
		Role: RoleRelay, Chunk: 16 << 10, Poll: 25 * time.Millisecond, Idle: -1,
	})
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		buf := make([]byte, 512)
		n, _ := relayEnd.Read(buf)
		relayEnd.Write([]byte("reply:" + string(buf[:n])))
	}()

	if _, err := clientEnd.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	if err := clientEnd.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := clientEnd.Read(buf)
	if err != nil || string(buf[:n]) != "reply:ping" {
		t.Fatalf("read: %q %v", buf[:n], err)
	}
}
