// Package route implements the "smart split": a local decision table that
// separates whitelisted destinations (reachable directly, without any tunnel)
// from everything else (which must go through a relay).
//
// In the whitelist model a large part of the user's traffic — Yandex, VK,
// Mail.ru, banks, government portals — is reachable as-is. Tunneling it
// through a relay wastes the relay's bandwidth and makes the traffic pattern
// stand out. The route table answers one question for every connection:
//
//	Direct  — the destination is inside the whitelist, go as usual;
//	Proxy   — unknown or explicitly marked, send it through the tunnel.
//
// The table matches domain suffixes (most specific rule wins, "proxy" wins
// ties) and IP prefixes. It is deliberately stdlib-only: net/netip provides
// prefix matching, and the embedded starter whitelist covers the biggest
// platforms out of the box.
package route

import (
	"net/netip"
	"strings"
)

// Action is the per-connection routing decision.
type Action int

const (
	// ActionProxy sends the connection through the relay. It is the default
	// for anything the table does not recognize: an unknown destination in
	// the whitelist model is presumably blocked.
	ActionProxy Action = iota
	// ActionDirect sends the connection straight out, bypassing the tunnel.
	ActionDirect
)

// String renders the action for logs.
func (a Action) String() string {
	if a == ActionDirect {
		return "direct"
	}
	return "proxy"
}

// Table is the decision table. Rules are added by the builder (see New and
// AddRule) and looked up per connection; lookups are read-only.
type Table struct {
	// direct and proxy hold domain suffix rules. A rule "yandex.ru" matches
	// yandex.ru itself and every subdomain.
	direct map[string]struct{}
	proxy  map[string]struct{}
	// cidrs holds IP prefix rules (direct only: whitelisted networks).
	cidrs []netip.Prefix
}

// New returns an empty table where every destination is proxied.
func New() *Table {
	return &Table{
		direct: make(map[string]struct{}),
		proxy:  make(map[string]struct{}),
	}
}

// AddRule adds a domain or CIDR rule. Rules are trimmed and lowercased;
// wildcard prefixes ("*.ya.ru"), schemes, ports and paths
// ("https://ya.ru:443/portal") are stripped so pasted rules just work.
func (t *Table) AddRule(rule string, direct bool) {
	rule = strings.TrimSpace(strings.ToLower(rule))
	if rule == "" {
		return
	}
	// CIDRs are parsed before any stripping: both separator characters
	// (":" and "/") also occur in CIDR notation.
	if p, err := netip.ParsePrefix(rule); err == nil {
		t.cidrs = append(t.cidrs, p.Masked())
		return
	}
	if i := strings.Index(rule, "://"); i >= 0 {
		rule = rule[i+3:]
	}
	if i := strings.Index(rule, "/"); i >= 0 {
		rule = rule[:i]
	}
	// A bare IP (optionally in brackets) is a single-address rule.
	if ip, err := netip.ParseAddr(strings.Trim(rule, "[]")); err == nil {
		bits := 32
		if ip.Is6() {
			bits = 128
		}
		t.cidrs = append(t.cidrs, netip.PrefixFrom(ip, bits).Masked())
		return
	}
	// Strip the port from domain rules; IPv6 literals were handled above.
	if i := strings.LastIndex(rule, ":"); i >= 0 && strings.Count(rule, ":") == 1 {
		rule = rule[:i]
	}
	rule = strings.TrimPrefix(rule, "*.")
	rule = strings.TrimSuffix(rule, ".")
	if rule == "" {
		return
	}
	if direct {
		t.direct[rule] = struct{}{}
	} else {
		t.proxy[rule] = struct{}{}
	}
}

// AddDirect adds rules that always bypass the tunnel.
func (t *Table) AddDirect(rules ...string) {
	for _, r := range rules {
		t.AddRule(r, true)
	}
}

// AddProxy adds rules that are forced through the tunnel.
func (t *Table) AddProxy(rules ...string) {
	for _, r := range rules {
		t.AddRule(r, false)
	}
}

// Decide resolves the action for addr, which may be a bare domain, an IP or
// a host:port pair (IPv6 in brackets). Domain matching walks the labels from
// the most specific suffix to the least; the first hit wins, and an explicit
// proxy rule beats a direct rule at the same level.
func (t *Table) Decide(addr string) Action {
	host, _, err := splitHostPort(addr)
	if err != nil {
		return ActionProxy
	}
	// Queries arrive in any case and sometimes carry a trailing dot.
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip, err := netip.ParseAddr(host); err == nil {
		for _, p := range t.cidrs {
			if p.Contains(ip.Unmap()) {
				return ActionDirect
			}
		}
		return ActionProxy
	}
	labels := strings.Split(host, ".")
	for i := range labels {
		suffix := strings.Join(labels[i:], ".")
		if _, ok := t.proxy[suffix]; ok {
			return ActionProxy
		}
		if _, ok := t.direct[suffix]; ok {
			return ActionDirect
		}
	}
	return ActionProxy
}

// splitHostPort splits host:port without touching the system resolver and
// accepts both "example.com:443" and "[2001:db8::1]:443".
func splitHostPort(addr string) (host string, port string, err error) {
	if i := strings.LastIndex(addr, "]"); i >= 0 {
		if !strings.HasPrefix(addr, "[") {
			return "", "", errBadAddr
		}
		host = addr[1:i]
		if len(addr) > i+1 && addr[i+1] == ':' {
			port = addr[i+2:]
		}
		return host, port, nil
	}
	if i := strings.LastIndex(addr, ":"); i >= 0 && strings.Count(addr, ":") == 1 {
		host, port = addr[:i], addr[i+1:]
		return host, port, nil
	}
	return addr, "", nil
}

type badAddrError struct{}

func (badAddrError) Error() string { return "route: bad address" }

var errBadAddr = badAddrError{}
