package mobile

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/mel0k1/qulogi/internal/engine"
)

const version = "0.1.0"

var (
	mu      sync.Mutex
	eng     *engine.Engine
	logSink func(string)
)

func Version() string {
	return version
}

func SetLogHandler(handler func(string)) {
	mu.Lock()
	logSink = handler
	mu.Unlock()
}

func forwardLog(msg string) {
	mu.Lock()
	sink := logSink
	mu.Unlock()
	if sink != nil {
		sink(msg)
	}
}

func Configure(config string) error {
	mu.Lock()
	defer mu.Unlock()
	var cfg engine.Config
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return fmt.Errorf("mobile: bad config: %w", err)
	}
	cfg.Log = forwardLog
	eng = engine.New(cfg)
	return nil
}

func Start() error {
	mu.Lock()
	defer mu.Unlock()
	if eng == nil {
		return fmt.Errorf("mobile: engine not configured")
	}
	return eng.Start()
}

func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if eng != nil {
		eng.Stop()
	}
}

func Status() string {
	mu.Lock()
	e := eng
	mu.Unlock()
	if e == nil {
		return "{}"
	}
	b, err := json.Marshal(e.Status())
	if err != nil {
		return "{}"
	}
	return string(b)
}
