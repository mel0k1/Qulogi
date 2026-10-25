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
		key   = flag.String("key", "", "Ed25519 seed, base64 (see -gen)")
		gen   = flag.Bool("gen", false, "generate a key pair and exit")
		in    = flag.String("in", "relays.json", "input: {\"relays\":[…]} or a bare array")
		out   = flag.String("out", "", "write the signed catalog here")
		ttl   = flag.Int("ttl", 120, "freshness window in minutes (0 = never expires)")
		keyID = flag.String("key-id", "", "signing key id, e.g. qulogi-dir-2026q4")
		txt   = flag.Bool("txt", false, "print TXT strings instead of writing a file")
		url   = flag.String("url", "", "TXT pointer mode: publish only this catalog URL")
		chunk = flag.Int("chunk", 200, "TXT chunk size in characters")
	)
	flag.Parse()

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
		relays := readRelays(*in)
		if len(relays) == 0 {
			fail("%s contains no relays", *in)
		}
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
	if err := json.Unmarshal(b, &wrap); err == nil && len(wrap.Relays) > 0 {
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
