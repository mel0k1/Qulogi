// Package discover implements the Qulogi relay directory: a signed catalog of
// relay transports, its verification, latency probing and best-candidate
// selection. It is the foundation of the "automatic relay search" feature
// described in docs/RELAY_DISCOVERY.md.
//
// A directory is a small JSON document, signed with Ed25519. Operators or the
// community publish it on several mirrors (plain HTTPS, DNS TXT, whitelisted
// storage, invites). The client fetches whatever mirror it can reach, checks
// the signature against a pinned key, probes every transport and picks the
// fastest one.
package discover

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// DirectoryVersion is the current catalog format version.
const DirectoryVersion = 1

// Transport describes one way to reach a relay. Type names form the adapter
// registry; see docs/RELAY_DISCOVERY.md for the full list.
type Transport struct {
	// Type is the adapter name: "qulogi-tls", "qulogi-tcp", "storage-webdav",
	// "bot-longpoll", "cdn-front", ...
	Type string `json:"type"`
	// Addr is the transport address: host:port for tcp-backed types, a URL
	// for http-backed ones.
	Addr string `json:"addr"`
	// SNI is the camouflage ServerName for qulogi transports.
	SNI string `json:"sni,omitempty"`
	// FP is the expected sha256 fingerprint of the relay TLS certificate
	// (base64, no padding). Empty means trust the WebPKI chain instead.
	FP string `json:"fp,omitempty"`
}

// Relay is a single relay and every transport it can be reached by.
type Relay struct {
	ID     string `json:"id"`
	Region string `json:"region,omitempty"`
	// Weight is the operator hint in [0..100]: higher means "prefer me".
	// It discounts the measured RTT by up to 50%.
	Weight     int         `json:"weight,omitempty"`
	Comment    string      `json:"comment,omitempty"`
	Transports []Transport `json:"transports"`
}

// Directory is a signed catalog of relays.
type Directory struct {
	Version int       `json:"version"`
	Updated time.Time `json:"updated"`
	// TTLMin is the freshness window in minutes; 0 means "never expires".
	TTLMin int     `json:"ttl_min,omitempty"`
	Relays []Relay `json:"relays"`
	// KeyID names the signing key so mirrors can rotate keys gracefully.
	KeyID string `json:"key_id,omitempty"`
	// Sig is the base64 Ed25519 signature over the canonical form of the
	// directory (the same JSON with Sig cleared).
	Sig string `json:"sig,omitempty"`
}

var (
	ErrBadSignature = errors.New("discover: bad directory signature")
	ErrNoSignature  = errors.New("discover: directory is not signed")
	ErrExpired      = errors.New("discover: directory expired")
)

// canonical renders the directory for signing: the exact JSON that is
// transmitted, with the signature field cleared.
func (d *Directory) canonical() ([]byte, error) {
	c := *d
	c.Sig = ""
	return json.Marshal(&c)
}

// Sign sets Version and fills Sig with an Ed25519 signature over the
// canonical form.
func (d *Directory) Sign(key ed25519.PrivateKey) error {
	d.Version = DirectoryVersion
	payload, err := d.canonical()
	if err != nil {
		return err
	}
	d.Sig = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, payload))
	return nil
}

// Verify checks the signature with pub and, if TTLMin is set, the freshness
// window against now.
func (d *Directory) Verify(pub ed25519.PublicKey, now time.Time) error {
	if d.Sig == "" {
		return ErrNoSignature
	}
	payload, err := d.canonical()
	if err != nil {
		return err
	}
	sig, err := base64.RawStdEncoding.DecodeString(d.Sig)
	if err != nil || !ed25519.Verify(pub, payload, sig) {
		return ErrBadSignature
	}
	if d.TTLMin > 0 {
		if deadline := d.Updated.Add(time.Duration(d.TTLMin) * time.Minute); now.After(deadline) {
			return fmt.Errorf("%w (%s ago)", ErrExpired, now.Sub(deadline).Round(time.Second))
		}
	}
	return nil
}

// Validate performs structural checks that do not require the signing key.
func (d *Directory) Validate() error {
	if d.Version != DirectoryVersion {
		return fmt.Errorf("discover: unsupported directory version %d", d.Version)
	}
	if d.Updated.IsZero() {
		return errors.New("discover: directory has no update timestamp")
	}
	seen := make(map[string]bool, len(d.Relays))
	for _, r := range d.Relays {
		if r.ID == "" {
			return errors.New("discover: relay without id")
		}
		if seen[r.ID] {
			return fmt.Errorf("discover: duplicate relay id %q", r.ID)
		}
		seen[r.ID] = true
		if len(r.Transports) == 0 {
			return fmt.Errorf("discover: relay %q has no transports", r.ID)
		}
		for _, t := range r.Transports {
			if t.Type == "" || t.Addr == "" {
				return fmt.Errorf("discover: relay %q has a transport without type or addr", r.ID)
			}
		}
	}
	return nil
}

// RelayByID returns the relay with the given id.
func (d *Directory) RelayByID(id string) (Relay, bool) {
	for _, r := range d.Relays {
		if r.ID == id {
			return r, true
		}
	}
	return Relay{}, false
}
