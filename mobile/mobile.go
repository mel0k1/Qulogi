// Package mobile exposes the Qulogi engine to platform bindings
// (gomobile for Android, gobind/xcframework for iOS). Two APIs live here:
//
//   - the classic SOCKS5 engine (Configure/Start/Stop/Status);
//   - the VPN engine (ConfigureVPN/StartVPN/StopVPN) which feeds packets
//     from the platform TUN device through a gVisor netstack into the
//     engine dialer.
package mobile

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/mel0k1/qulogi/internal/engine"
	"github.com/mel0k1/qulogi/internal/vpn"
)

const version = "0.6.0"

var (
	mu        sync.Mutex
	eng       *engine.Engine
	logSink   LogSink
	protector Protector

	vpnStack *vpn.Stack
	vpnConf  *engine.Config
	vpnUp    *engine.Engine // dialer provider for vpn mode
)

// LogSink receives engine log lines on the platform side (gomobile needs a
// named interface; bare func types are not bindable).
type LogSink interface {
	Log(line string)
}

// Protector marks outbound sockets as exempt from the platform VPN routing
// (VpnService.protect on Android). Implemented on the platform side and
// injected via SetProtector.
type Protector interface {
	Protect(fd int32) bool
}

func Version() string {
	return version
}

// SetLogSink wires the platform log receiver.
func SetLogSink(sink LogSink) {
	mu.Lock()
	logSink = sink
	mu.Unlock()
}

func forwardLog(msg string) {
	mu.Lock()
	sink := logSink
	mu.Unlock()
	if sink != nil {
		sink.Log(msg)
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

// SetProtector injects the platform socket-protect callback.
func SetProtector(p Protector) {
	mu.Lock()
	protector = p
	mu.Unlock()
}

// ConfigureVPN parses and stores the VPN engine configuration. The same
// JSON schema as Configure is used; unknown fields are ignored.
func ConfigureVPN(config string) error {
	mu.Lock()
	defer mu.Unlock()
	var cfg engine.Config
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return fmt.Errorf("mobile: bad vpn config: %w", err)
	}
	cfg.Mode = engine.ModeVPN
	cfg.Log = forwardLog
	dialer := engine.New(cfg)
	vpnConf = &cfg
	vpnUp = dialer
	eng = dialer
	return nil
}

// StartVPN attaches the TUN file descriptor and starts the netstack.
func StartVPN(fd int32, mtu int32) error {
	mu.Lock()
	defer mu.Unlock()
	if vpnUp == nil {
		return fmt.Errorf("mobile: vpn not configured")
	}
	if vpnStack != nil {
		return fmt.Errorf("mobile: vpn already running")
	}
	up, down := vpnUp.Counters()
	cfg := vpn.Config{
		FD:   int(fd),
		MTU:  uint32(mtu),
		Dial: vpnUp.DialContext,
		// Per-flow UDP policy from the smart split route table; TCP
		// decisions happen inside DialContext itself.
		UDPRoute: func(host string, port int) string {
			return vpnUp.RouteDecision("udp", net.JoinHostPort(host, strconv.Itoa(port)))
		},
		Egress: vpnEgress(vpnConf),
		Log:    forwardLog,
		Up:     up,
		Down:   down,
	}
	// SNI sniffing: with a relay and the smart split enabled, TCP flows
	// are routed by the hostname from the ClientHello, not just by IP.
	if vpnConf != nil && hasRelay(vpnConf) && vpnConf.SmartSplit {
		cfg.RouteSNI = func(sni, dst string) string {
			return vpnUp.RouteDomain(sni, dst)
		}
		cfg.DialVia = vpnUp.DialVia
	}
	// UDP over the tunnel: QUIC and friends ride the relay as framed
	// datagrams instead of being dropped.
	if vpnConf != nil && hasRelay(vpnConf) {
		cfg.DialPacket = vpnUp.DialPacket
	}
	st, err := vpn.New(cfg)
	if err != nil {
		return err
	}
	vpnStack = st
	st.Run()
	return nil
}

func vpnEgress(cfg *engine.Config) string {
	if cfg == nil || !hasRelay(cfg) {
		return vpn.EgressDirect
	}
	if cfg.SmartSplit {
		return vpn.EgressSplit
	}
	return vpn.EgressTunnel
}

// hasRelay reports whether the config carries an upstream relay of any
// transport class, including failover reserves.
func hasRelay(cfg *engine.Config) bool {
	return cfg.Server != "" || cfg.DAVURL != "" || cfg.CDNEdge != "" ||
		cfg.BotLPURL != "" || cfg.TURNServer != "" || len(cfg.Fallbacks) > 0
}

// StopVPN halts the netstack and releases the TUN device.
func StopVPN() {
	mu.Lock()
	st := vpnStack
	vpnStack = nil
	e := vpnUp
	mu.Unlock()
	if st != nil {
		st.Stop()
	}
	if e != nil {
		e.Stop() // also stops the failover monitor
	}
}

// SetBlocked toggles the kill switch: while blocked every new flow is
// refused, so no traffic can leak when the tunnel is unhealthy.
func SetBlocked(blocked bool) {
	mu.Lock()
	st := vpnStack
	mu.Unlock()
	if st != nil {
		st.SetBlocked(blocked)
	}
}

// VpnStatus returns a JSON snapshot of the VPN transport state.
func VpnStatus() string {
	mu.Lock()
	st := vpnStack
	e := vpnUp
	mu.Unlock()
	if st == nil {
		return "{}"
	}
	snap := st.Snapshot()
	if e != nil {
		es := e.Status()
		snap.Up = es.BytesUp
		snap.Down = es.BytesDown
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return "{}"
	}
	return string(b)
}
