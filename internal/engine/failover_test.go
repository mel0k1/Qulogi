package engine

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mel0k1/qulogi/internal/tunnel"
)

// testLogGuards returns an engine log sink and a stop func that silences
// it: the failover monitor can outlive the test body by one probe cycle.
func testLogGuards(t *testing.T) (func(string), func()) {
	var done atomic.Bool
	return func(msg string) {
		if !done.Load() {
			t.Log(msg)
		}
	}, func() { done.Store(true) }
}

// TestFailoverOnPrimaryFailure: the primary transport dies, the reserve
// picks the traffic up and becomes the sticky active transport.
func TestFailoverOnPrimaryFailure(t *testing.T) {
	psk := "fo-psk"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("QULOGI_FAILOVER"))
	}))
	defer target.Close()

	relayB := startRelay(t, psk)
	logFn, stopLog := testLogGuards(t)

	e := New(Config{
		Mode:   ModeTunnel,
		Listen: "127.0.0.1:0",
		Server: "127.0.0.1:1", // nothing listens here
		PSK:    psk,
		Fallbacks: []TransportSpec{
			{Kind: "tcp", Server: relayB},
		},
		Log: logFn,
	})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		stopLog()
		e.Stop()
	}()

	dst := strings.TrimPrefix(target.URL, "http://")
	if body := socks5Fetch(t, e.Status().Listen, dst); !strings.Contains(body, "QULOGI_FAILOVER") {
		t.Fatalf("body: %q", body)
	}
	// The primary is dead from the start: the first flow already
	// switches to the reserve.
	st := e.Status()
	if st.Failovers != 1 {
		t.Fatalf("failovers after first flow: %d", st.Failovers)
	}
	if st.Transport != "tcp:"+relayB {
		t.Fatalf("active transport: %q", st.Transport)
	}

	// Sticky: the next flows go straight to the reserve.
	for i := 0; i < 2; i++ {
		if body := socks5Fetch(t, e.Status().Listen, dst); !strings.Contains(body, "QULOGI_FAILOVER") {
			t.Fatalf("sticky round %d body: %q", i, body)
		}
	}
	if st := e.Status(); st.Failovers != 1 {
		t.Fatalf("sticky flow touched the dead primary again: %d", st.Failovers)
	}
}

// TestFailoverMonitorSwitch: the background monitor detects the primary
// degradation and moves the chain head to the reserve without traffic.
func TestFailoverMonitorSwitch(t *testing.T) {
	psk := "mon-psk"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("QULOGI_MON"))
	}))
	defer target.Close()

	// Relay A is a standalone listener we can kill mid-test.
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var doneA atomic.Bool
	srvA := &tunnel.Server{Listener: lnA, PSK: []byte(psk), Log: func(msg string) {
		if !doneA.Load() {
			t.Log("relayA:", msg)
		}
	}}
	go srvA.Serve()
	relayA := lnA.Addr().String()

	relayB := startRelay(t, psk)
	logFn, stopLog := testLogGuards(t)

	e := New(Config{
		Mode:              ModeTunnel,
		Listen:            "127.0.0.1:0",
		Server:            relayA,
		PSK:               psk,
		FailoverProbeSecs: 1,
		Fallbacks:         []TransportSpec{{Kind: "tcp", Server: relayB}},
		Log:               logFn,
	})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		stopLog()
		e.Stop()
	}()

	dst := strings.TrimPrefix(target.URL, "http://")
	if body := socks5Fetch(t, e.Status().Listen, dst); !strings.Contains(body, "QULOGI_MON") {
		t.Fatalf("body: %q", body)
	}
	if st := e.Status(); st.Transport != "tcp:"+relayA {
		t.Fatalf("initial transport: %q", st.Transport)
	}

	// The monitor starts lazily on the first tunnel dial; give it a
	// cycle, then kill the primary.
	time.Sleep(1200 * time.Millisecond)
	doneA.Store(true)
	_ = lnA.Close()

	deadline := time.Now().Add(6 * time.Second)
	for {
		st := e.Status()
		if st.Transport == "tcp:"+relayB && st.Failovers >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("monitor did not switch: transport=%q failovers=%d", st.Transport, st.Failovers)
		}
		time.Sleep(300 * time.Millisecond)
	}

	// Traffic still flows through the reserve.
	if body := socks5Fetch(t, e.Status().Listen, dst); !strings.Contains(body, "QULOGI_MON") {
		t.Fatalf("body after monitor switch: %q", body)
	}
}

// TestFailoverDisabled: NoFailover keeps everything on the primary.
func TestFailoverDisabled(t *testing.T) {
	psk := "nof-psk"
	relay := startRelay(t, psk)
	logFn, stopLog := testLogGuards(t)

	e := New(Config{
		Mode:       ModeTunnel,
		Listen:     "127.0.0.1:0",
		Server:     "127.0.0.1:1",
		PSK:        psk,
		NoFailover: true,
		Fallbacks:  []TransportSpec{{Kind: "tcp", Server: relay}},
		Log:        logFn,
	})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		stopLog()
		e.Stop()
	}()
	time.Sleep(1500 * time.Millisecond)
	if st := e.Status(); st.Failovers != 0 {
		t.Fatalf("failover happened despite NoFailover: %d", st.Failovers)
	}
}

// TestFailoverFallbackOnlyConfig: no primary, reserves only.
func TestFailoverFallbackOnlyConfig(t *testing.T) {
	psk := "fb-only"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("QULOGI_FB_ONLY"))
	}))
	defer target.Close()
	relay := startRelay(t, psk)
	logFn, stopLog := testLogGuards(t)

	e := New(Config{
		Mode:      ModeTunnel,
		Listen:    "127.0.0.1:0",
		PSK:       psk,
		Fallbacks: []TransportSpec{{Kind: "tcp", Server: relay}},
		Log:       logFn,
	})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		stopLog()
		e.Stop()
	}()
	body := socks5Fetch(t, e.Status().Listen, strings.TrimPrefix(target.URL, "http://"))
	if !strings.Contains(body, "QULOGI_FB_ONLY") {
		t.Fatalf("body: %q", body)
	}
}

// TestFailoverValidation checks Start rejects broken reserve specs.
func TestFailoverValidation(t *testing.T) {
	cases := []struct {
		name string
		spec TransportSpec
	}{
		{"unknown kind", TransportSpec{Kind: "ldap", Server: "x"}},
		{"tcp without server", TransportSpec{Kind: "tcp"}},
		{"cdn without host", TransportSpec{Kind: "cdn", Server: "edge:443"}},
		{"dav without url", TransportSpec{Kind: "dav"}},
		{"turn without peer", TransportSpec{Kind: "turn", Server: "t:3478"}},
		{"botlp bad api", TransportSpec{Kind: "botlp"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(Config{
				Mode:      ModeTunnel,
				Listen:    "127.0.0.1:0",
				PSK:       "x",
				Fallbacks: []TransportSpec{tc.spec},
			})
			if err := e.Start(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
