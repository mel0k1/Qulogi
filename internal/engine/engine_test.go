package engine

import "testing"

func TestRouteDecision(t *testing.T) {
	// VPN with a relay and the smart split on.
	e := New(Config{Mode: ModeVPN, Server: "r1.example.net:443", PSK: "k", SmartSplit: true})
	if got := e.RouteDecision("tcp", "ya.ru:443"); got != "direct" {
		t.Errorf("whitelisted host: %v, want direct", got)
	}
	if got := e.RouteDecision("tcp", "77.88.8.8:53"); got != "direct" {
		t.Errorf("whitelisted ip: %v, want direct", got)
	}
	if got := e.RouteDecision("tcp", "example.org:443"); got != "tunnel" {
		t.Errorf("unknown host: %v, want tunnel", got)
	}

	// Without a relay everything is direct.
	e2 := New(Config{Mode: ModeVPN})
	if got := e2.RouteDecision("tcp", "example.org:443"); got != "direct" {
		t.Errorf("no relay: %v, want direct", got)
	}

	// Split off: everything rides the tunnel.
	e3 := New(Config{Mode: ModeTunnel, Server: "r:443", PSK: "k"})
	if got := e3.RouteDecision("tcp", "ya.ru:443"); got != "tunnel" {
		t.Errorf("split off: %v, want tunnel", got)
	}

	// User overrides: proxy rule beats the embedded whitelist,
	// direct rule covers the unknown.
	e4 := New(Config{
		Mode: ModeTunnel, Server: "r:443", PSK: "k", SmartSplit: true,
		Proxy:  []string{"vk.com"},
		Direct: []string{"mycdn.example.org", "10.0.0.0/8"},
	})
	if got := e4.RouteDecision("tcp", "vk.com:443"); got != "tunnel" {
		t.Errorf("proxy override: %v, want tunnel", got)
	}
	if got := e4.RouteDecision("tcp", "sub.mycdn.example.org:443"); got != "direct" {
		t.Errorf("direct override: %v, want direct", got)
	}
	if got := e4.RouteDecision("tcp", "10.1.2.3:8080"); got != "direct" {
		t.Errorf("cidr override: %v, want direct", got)
	}
}
