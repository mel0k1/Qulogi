package discover

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func probeStub(lat map[string]time.Duration) ProbeFunc {
	return func(_ context.Context, _ Relay, t Transport) (time.Duration, error) {
		if d, ok := lat[t.Addr]; ok {
			return d, nil
		}
		return 0, errors.New("unreachable")
	}
}

func pickFixture() *Directory {
	return &Directory{
		Updated: time.Now().UTC(),
		Relays: []Relay{
			{ID: "slow", Transports: []Transport{{Type: "qulogi-tls", Addr: "slow:443"}}},
			{ID: "fast", Transports: []Transport{{Type: "qulogi-tls", Addr: "fast:443"}}},
			{ID: "mid", Transports: []Transport{{Type: "qulogi-tls", Addr: "mid:443"}}},
			{ID: "dead", Transports: []Transport{{Type: "qulogi-tls", Addr: "dead:443"}}},
		},
	}
}

func TestPickOrdersByLatency(t *testing.T) {
	lat := map[string]time.Duration{
		"slow:443": 120 * time.Millisecond,
		"fast:443": 40 * time.Millisecond,
		"mid:443":  80 * time.Millisecond,
	}
	res := Pick(context.Background(), pickFixture(), 2, time.Second, probeStub(lat))
	if len(res) != 2 {
		t.Fatalf("want 2 results, got %d", len(res))
	}
	if res[0].Relay.ID != "fast" || res[1].Relay.ID != "mid" {
		t.Fatalf("wrong order: %s then %s", res[0].Relay.ID, res[1].Relay.ID)
	}
	for _, r := range res {
		if r.Err != nil {
			t.Fatalf("unexpected error for %s: %v", r.Relay.ID, r.Err)
		}
	}
}

func TestPickWeightDiscount(t *testing.T) {
	dir := &Directory{Updated: time.Now().UTC(), Relays: []Relay{
		{ID: "plain", Transports: []Transport{{Type: "qulogi-tls", Addr: "plain:443"}}},
		// heavy RTT but the operator asks to prefer it
		{ID: "heavy", Weight: 100, Transports: []Transport{{Type: "qulogi-tls", Addr: "heavy:443"}}},
	}}
	lat := map[string]time.Duration{
		"plain:443": 80 * time.Millisecond,
		"heavy:443": 90 * time.Millisecond, // score 45ms after the 50% discount
	}
	res := Pick(context.Background(), dir, 2, time.Second, probeStub(lat))
	if res[0].Relay.ID != "heavy" {
		t.Fatalf("weight discount failed: winner is %s", res[0].Relay.ID)
	}
}

func TestPickDropsDead(t *testing.T) {
	res := Pick(context.Background(), pickFixture(), 4, time.Second,
		probeStub(map[string]time.Duration{"fast:443": time.Millisecond}))
	if len(res) != 1 || res[0].Relay.ID != "fast" {
		t.Fatalf("want single live relay, got %+v", res)
	}
}

func TestPickEmptyDirectory(t *testing.T) {
	if res := Pick(context.Background(), &Directory{}, 3, time.Second, nil); res != nil {
		t.Fatalf("want nil, got %+v", res)
	}
}

func TestProbeDialAddrParsing(t *testing.T) {
	cases := []struct {
		in   Transport
		want string
		err  error
	}{
		{Transport{Addr: "r.example.com:443"}, "r.example.com:443", nil},
		{Transport{Addr: "https://disk.example.com"}, "disk.example.com:443", nil},
		{Transport{Addr: "http://disk.example.com:8080/x"}, "disk.example.com:8080", nil},
		{Transport{Addr: ""}, "", ErrNoAddress},
		{Transport{Addr: "https://"}, "", ErrNoAddress},
	}
	for _, c := range cases {
		got, err := dialAddr(c.in)
		if c.err != nil {
			if !errors.Is(err, c.err) {
				t.Errorf("dialAddr(%q) error = %v, want %v", c.in.Addr, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("dialAddr(%q) unexpected error: %v", c.in.Addr, err)
			continue
		}
		if got != c.want {
			t.Errorf("dialAddr(%q) = %q, want %q", c.in.Addr, got, c.want)
		}
	}
}

func TestProbeRealListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no local listener available:", err)
	}
	defer ln.Close()
	rtt, err := Probe(context.Background(), Transport{Type: "qulogi-tls", Addr: ln.Addr().String()})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("suspicious rtt %v", rtt)
	}
}
