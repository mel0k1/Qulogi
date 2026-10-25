// qulogicat builds and signs relay catalogs for the Qulogi discovery
// system (docs/RELAY_DISCOVERY.md). An operator keeps a plain JSON list of
// relays, signs it with an Ed25519 key and publishes the result on any
// static mirror — GitHub Pages, jsDelivr, a whitelisted CDN — plus (as
// base64 chunks or a pointer) in DNS TXT records.
//
//	# one-time: generate a signing key
//	qulogicat -gen
//
//	# sign the relay list into catalog.json
//	qulogicat -key <seed-b64> -in relays.json -out catalog.json -ttl 120
//
//	# the TXT strings to put into the zone (chunks or a pointer)
//	qulogicat -key <seed> -in relays.json -txt
//	qulogicat -txt -url https://mirror.example/catalog.json
//
//	# verify a published catalog against the pinned public key
//	qulogicat -verify -in catalog.json -pub <public-b64>
//
// The client pins the public key, so a compromised mirror cannot inject
// relays — it can only serve an older, still-signed catalog.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mel0k1/qulogi/internal/discover"
)

func main() {
	var (
		key    = flag.String("key", "", "Ed25519 seed, base64 (see -gen)")
		gen    = flag.Bool("gen", false, "generate a key pair and exit")
		in     = flag.String("in", "relays.json", "input: {\"relays\":[…]}, a bare array, or a catalog to verify (with -verify)")
		out    = flag.String("out", "", "write the signed catalog here")
		ttl    = flag.Int("ttl", 120, "freshness window in minutes (0 = never expires)")
		keyID  = flag.String("key-id", "", "signing key id, e.g. qulogi-dir-2026q4")
		txt    = flag.Bool("txt", false, "print TXT strings instead of writing a file")
		url    = flag.String("url", "", "TXT pointer mode: publish only this catalog URL")
		chunk  = flag.Int("chunk", 200, "TXT chunk size in characters")
		verify = flag.Bool("verify", false, "verify a catalog file against -pub and exit")
		pub    = flag.String("pub", "", "Ed25519 public key, base64 (with -verify)")
	)
	flag.Parse()

	if *verify {
		os.Exit(verifyCatalog(*in, *pub))
	}

	if *gen {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fail("generate: %v", err)
		}
		fmt.Printf("seed:    %s\npublic:  %s\n", base64.StdEncoding.EncodeToString(priv.Seed()),
			base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
		return
	}

	var priv ed25519.PrivateKey
	if *key != "" {
		seed, err := base64.StdEncoding.DecodeString(*key)
		if err != nil || len(seed) != ed25519.SeedSize {
			fail("bad -key: expected %d base64 bytes", ed25519.SeedSize)
		}
		priv = ed25519.NewKeyFromSeed(seed)
	}

	var payload []byte
	switch {
	case *url != "":
		payload = []byte(*url)
	default:
		// An empty relay list is legitimate: a fresh community
		// catalog starts empty and fills in via pull requests.
		relays := readRelays(*in)
		dir := &discover.Directory{
			Updated: time.Now().UTC().Truncate(time.Second),
			TTLMin:  *ttl,
			KeyID:   *keyID,
			Relays:  relays,
		}
		if priv != nil {
			if err := dir.Sign(priv); err != nil {
				fail("sign: %v", err)
			}
		}
		b, err := json.Marshal(dir)
		if err != nil {
			fail("marshal: %v", err)
		}
		payload = b
	}

	if *txt {
		if *url != "" {
			fmt.Println(*url)
			return
		}
		b64 := base64.StdEncoding.EncodeToString(payload)
		for i := 0; i < len(b64); i += *chunk {
			end := i + *chunk
			if end > len(b64) {
				end = len(b64)
			}
			fmt.Printf("%02x%s\n", i/(*chunk), b64[i:end])
		}
		return
	}

	if *out == "" {
		os.Stdout.Write(payload)
		fmt.Println()
		return
	}
	if err := os.WriteFile(*out, append(payload, '\n'), 0o644); err != nil {
		fail("write: %v", err)
	}
	fmt.Printf("qulogicat: signed catalog written to %s (%d relays, ttl %d min)\n",
		*out, len(readRelays(*in)), *ttl)
}

// readRelays accepts {"relays":[…]} or a bare JSON array of relays.
func readRelays(path string) []discover.Relay {
	b, err := os.ReadFile(path)
	if err != nil {
		fail("read %s: %v", path, err)
	}
	var wrap struct {
		Relays []discover.Relay `json:"relays"`
	}
	if err := json.Unmarshal(b, &wrap); err == nil && wrap.Relays != nil {
		// A well-formed wrapper object wins even when the list is
		// empty: a fresh community catalog starts with zero relays.
		return wrap.Relays
	}
	var arr []discover.Relay
	if err := json.Unmarshal(b, &arr); err != nil {
		fail("parse %s: %v", path, err)
	}
	return arr
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "qulogicat: "+strings.TrimSuffix(format, "\n")+"\n", args...)
	os.Exit(1)
}

// verifyCatalog loads a published catalog, checks its structure and its
// Ed25519 signature (plus the TTL) against the pinned public key. Exit
// codes: 0 ok, 1 bad catalog, 2 usage error. CI of the community catalog
// runs this on every pull request.
func verifyCatalog(path, pubB64 string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "qulogicat: read %s: %v\n", path, err)
		return 1
	}
	if pubB64 == "" {
		fmt.Fprintln(os.Stderr, "qulogicat: -verify requires -pub <base64 public key>")
		return 2
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		fmt.Fprintln(os.Stderr, "qulogicat: bad -pub: expected 32 base64 bytes")
		return 2
	}
	var dir discover.Directory
	if err := json.Unmarshal(b, &dir); err != nil {
		fmt.Fprintf(os.Stderr, "qulogicat: %s is not a catalog: %v\n", path, err)
		return 1
	}
	if err := dir.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "qulogicat: %s: %v\n", path, err)
		return 1
	}
	if err := dir.Verify(ed25519.PublicKey(raw), time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "qulogicat: %s: %v\n", path, err)
		return 1
	}
	fmt.Printf("qulogicat: %s ok (%d relays, key %s, updated %s)\n",
		path, len(dir.Relays), dir.KeyID, dir.Updated.Format(time.RFC3339))
	return 0
}
