package mobile

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mel0k1/qulogi/internal/discover"
)

// FetchDirectoryParams selects the mirrors to race and the verification key.
type fetchParams struct {
	// Sources overrides the built-in mirror list when non-empty.
	Sources []discover.Source `json:"sources,omitempty"`
	// PubKey is the base64 Ed25519 catalog key; empty disables signature
	// pinning (the catalog is only structurally validated).
	PubKey string `json:"pubkey,omitempty"`
	// CachePath persists the last good directory. When every mirror is
	// unreachable the cache is served instead (from_cache=true).
	CachePath string `json:"cache_path,omitempty"`
	// ProbeN is how many live transports to report (default 5).
	ProbeN int `json:"probe,omitempty"`
	// ProbeBudget bounds each transport probe (default 3s).
	ProbeBudgetMS int `json:"probe_budget_ms,omitempty"`
}

type probeRow struct {
	RelayID string  `json:"relay_id"`
	Type    string  `json:"type"`
	Addr    string  `json:"addr"`
	SNI     string  `json:"sni,omitempty"`
	RTTMS   float64 `json:"rtt_ms"`
}

type fetchResult struct {
	Directory *discover.Directory `json:"directory,omitempty"`
	Source    string              `json:"source,omitempty"`
	Verified  bool                `json:"verified"`
	FromCache bool                `json:"from_cache"`
	Probes    []probeRow          `json:"probes"`
	Error     string              `json:"error,omitempty"`
}

// FetchDirectory races the catalog mirrors (HTTPS, DNS TXT, DoH), verifies
// the signature, probes the transports and returns a JSON report:
//
//	{"directory":{...},"source":"https:...","verified":true,"from_cache":false,
//	 "probes":[{"relay_id":"owl-eu-1","type":"qulogi-tls","addr":"r1:443","rtt_ms":42.1}]}
//
// On total failure it falls back to the last good cache; if that fails too,
// the report carries an "error" field.
func FetchDirectory(params string) string {
	res := fetchResult{}
	defer func() {
		if r := recover(); r != nil {
			res.Error = fmt.Sprintf("mobile: panic: %v", r)
		}
	}()
	var p fetchParams
	if err := json.Unmarshal([]byte(params), &p); err != nil {
		return reportJSON(fetchResult{Error: fmt.Sprintf("mobile: bad params: %v", err)})
	}
	var pub ed25519.PublicKey
	if p.PubKey != "" {
		key, err := base64.StdEncoding.DecodeString(p.PubKey)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return reportJSON(fetchResult{Error: "mobile: bad pubkey"})
		}
		pub = ed25519.PublicKey(key)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	res2, err := discover.Fetch(ctx, p.Sources, pub, nil)
	if err != nil {
		if cache, cerr := discover.LoadCache(p.CachePath); cerr == nil && cache != nil &&
			cache.Directory.Validate() == nil {
			res.Directory = cache.Directory
			res.Source = cache.Source
			res.FromCache = true
		} else {
			return reportJSON(fetchResult{Error: err.Error()})
		}
	} else {
		res.Directory = res2.Directory
		res.Source = res2.Source
		res.Verified = res2.Verified
		if p.CachePath != "" {
			_ = discover.SaveCache(p.CachePath, res2.Directory, res2.Source)
		}
	}

	n := p.ProbeN
	if n <= 0 {
		n = 5
	}
	budget := time.Duration(p.ProbeBudgetMS) * time.Millisecond
	if budget <= 0 {
		budget = 3 * time.Second
	}
	pctx, pcancel := context.WithTimeout(context.Background(), budget+time.Second)
	defer pcancel()
	live := discover.Pick(pctx, res.Directory, n, budget, discover.DefaultProbe)
	for _, pr := range live {
		res.Probes = append(res.Probes, probeRow{
			RelayID: pr.Relay.ID,
			Type:    pr.Transport.Type,
			Addr:    pr.Transport.Addr,
			SNI:     pr.Transport.SNI,
			RTTMS:   float64(pr.RTT) / float64(time.Millisecond),
		})
	}
	return reportJSON(res)
}

func reportJSON(r fetchResult) string {
	b, err := json.Marshal(r)
	if err != nil {
		return `{"error":"mobile: marshal"}`
	}
	return string(b)
}
