// qulogi:// invites: share a single relay without any catalog. The link is
// short enough to fit a QR code and carries everything the client needs:
//
//	qulogi://relay/<id>?type=qulogi-tls&addr=r1.example.net%3A443&sni=vkvideo.ru&fp=<b64>&psk=<secret>
//	qulogi://catalog/?url=https%3A%2F%2F...&name=Community
//
// The psk parameter is unavoidable for private relays (the client must
// authenticate to qulogid), so an invite is a secret: publish it the way
// you would publish a password.
package discover

import (
	"fmt"
	"net/url"
	"strings"
)

// Invite is a parsed qulogi:// link.
type Invite struct {
	// Kind is "relay" or "catalog".
	Kind string
	// Relay fields (Kind == "relay").
	ID        string
	Transport Transport
	PSK       string
	// CatalogURL (Kind == "catalog").
	CatalogURL string
}

// RelayInvite renders a relay invite link.
func RelayInvite(id string, t Transport, psk string) string {
	q := url.Values{}
	q.Set("type", t.Type)
	q.Set("addr", t.Addr)
	if t.SNI != "" {
		q.Set("sni", t.SNI)
	}
	if t.FP != "" {
		q.Set("fp", t.FP)
	}
	if psk != "" {
		q.Set("psk", psk)
	}
	u := url.URL{Scheme: "qulogi", Host: "relay", Path: "/" + id, RawQuery: q.Encode()}
	return u.String()
}

// CatalogInvite renders a catalog subscription link.
func CatalogInvite(rawURL, name string) string {
	q := url.Values{}
	q.Set("url", rawURL)
	if name != "" {
		q.Set("name", name)
	}
	u := url.URL{Scheme: "qulogi", Host: "catalog", Path: "/", RawQuery: q.Encode()}
	return u.String()
}

// ParseInvite parses and validates a qulogi:// link.
func ParseInvite(link string) (*Invite, error) {
	link = strings.TrimSpace(link)
	if link == "" {
		return nil, fmt.Errorf("discover: empty invite")
	}
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("discover: bad invite: %w", err)
	}
	if u.Scheme != "qulogi" {
		return nil, fmt.Errorf("discover: not a qulogi link (scheme %q)", u.Scheme)
	}
	q := u.Query()
	switch strings.ToLower(u.Host) {
	case "relay":
		inv := &Invite{Kind: "relay"}
		inv.ID = strings.Trim(u.Path, "/")
		t := Transport{Type: q.Get("type"), Addr: q.Get("addr"), SNI: q.Get("sni"), FP: q.Get("fp")}
		if t.Type == "" || t.Addr == "" {
			return nil, fmt.Errorf("discover: relay invite needs type and addr")
		}
		inv.Transport = t
		inv.PSK = q.Get("psk")
		return inv, nil
	case "catalog", "dir":
		cu := q.Get("url")
		if cu == "" {
			cu = q.Get("u")
		}
		if cu == "" || !(strings.HasPrefix(cu, "http://") || strings.HasPrefix(cu, "https://")) {
			return nil, fmt.Errorf("discover: catalog invite needs an http(s) url")
		}
		return &Invite{Kind: "catalog", CatalogURL: cu}, nil
	default:
		return nil, fmt.Errorf("discover: unknown invite kind %q", u.Host)
	}
}
