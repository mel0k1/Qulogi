package discover

import (
	"context"
	"sort"
	"sync"
	"time"
)

// ProbeResult is the outcome of probing a single transport.
type ProbeResult struct {
	Relay     Relay
	Transport Transport
	RTT       time.Duration
	Err       error
}

// ProbeFunc probes one transport. The default implementation is a plain TCP
// dial; adapters can provide richer health checks.
type ProbeFunc func(ctx context.Context, r Relay, t Transport) (time.Duration, error)

// DefaultProbe measures TCP dial latency.
func DefaultProbe(ctx context.Context, r Relay, t Transport) (time.Duration, error) {
	return Probe(ctx, t)
}

// Pick probes every transport of every relay concurrently and returns up to
// n live transports sorted by score: measured RTT with the operator weight
// discount applied. Unreachable transports are dropped; if nothing is alive
// the result is empty. budget bounds each individual probe.
func Pick(ctx context.Context, dir *Directory, n int, budget time.Duration, fn ProbeFunc) []ProbeResult {
	if fn == nil {
		fn = DefaultProbe
	}
	if n <= 0 {
		n = 1
	}
	type job struct {
		r Relay
		t Transport
	}
	var jobs []job
	for _, r := range dir.Relays {
		for _, t := range r.Transports {
			jobs = append(jobs, job{r, t})
		}
	}
	if len(jobs) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	sem := make(chan struct{}, 16)
	out := make(chan ProbeResult, len(jobs))
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rtt, err := fn(ctx, j.r, j.t)
			out <- ProbeResult{Relay: j.r, Transport: j.t, RTT: rtt, Err: err}
		}(j)
	}
	wg.Wait()
	close(out)

	var live []ProbeResult
	for res := range out {
		if res.Err == nil {
			live = append(live, res)
		}
	}
	sort.Slice(live, func(i, j int) bool {
		return score(live[i].RTT, live[i].Relay.Weight) < score(live[j].RTT, live[j].Relay.Weight)
	})
	if len(live) > n {
		live = live[:n]
	}
	return live
}

// score discounts the measured RTT by the operator weight: weight 100 halves
// the effective RTT, weight 0 leaves it as is.
func score(rtt time.Duration, weight int) float64 {
	if weight < 0 {
		weight = 0
	}
	if weight > 100 {
		weight = 100
	}
	return float64(rtt) * (1 - float64(weight)/200)
}
