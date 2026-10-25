// Package vpn implements a userspace TCP/IP stack (gVisor netstack) on top
// of a TUN file descriptor. It terminates TCP and UDP flows coming from the
// device and forwards them through the engine dialer (direct with DPI
// tricks or via the encrypted tunnel).
package vpn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Egress selects how flows are forwarded.
const (
	EgressTunnel = "tunnel"
	EgressDirect = "direct"
	// EgressSplit is the smart split: DNS goes over the tunnel, TCP flows
	// are decided per connection by Dial (which consults the route table)
	// and non-DNS UDP by UDPRoute.
	EgressSplit = "split"
)

// Config wires the stack to the platform TUN device and the engine dialer.
type Config struct {
	// FD is the TUN file descriptor (from Android VpnService.establish).
	FD int
	// MTU matches the TUN interface MTU. 8500 is a good trade-off for
	// userspace stacks: fewer wakeups, still one packet per read.
	MTU uint32
	// Dial performs the upstream connection. All sockets it creates must
	// already be protected from being routed back into the VPN.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Egress selects the default UDP policy: with EgressTunnel only DNS is
	// relayed (over TCP inside the tunnel); with EgressDirect all UDP
	// flows are relayed as-is; EgressSplit consults UDPRoute per flow.
	Egress string
	// UDPRoute maps a non-DNS UDP flow to a policy: "direct", "tunnel"
	// (unsupported for UDP, becomes a drop) or "drop". When EgressSplit
	// is on and UDPRoute is nil, all non-DNS UDP is dropped.
	UDPRoute func(dstHost string, dstPort int) string `json:"-"`
	// Log receives human readable events.
	Log func(string)
	// Up/Down collect relayed bytes for the status screen.
	Up   *atomic.Int64
	Down *atomic.Int64
}

// Status is a snapshot for the UI layer.
type Status struct {
	Running bool   `json:"running"`
	Blocked bool   `json:"blocked"`
	Flows   int64  `json:"flows"`
	Up      int64  `json:"up"`
	Down    int64  `json:"down"`
	Egress  string `json:"egress"`
}

// Stack owns the netstack and the TUN pump goroutines.
type Stack struct {
	cfg Config

	dev    *os.File
	ep     *channel.Endpoint
	net    *stack.Stack
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	blocked  atomic.Bool
	flows    atomic.Int64
	dnsOnce  sync.Once
	stopOnce sync.Once
}

// New builds the stack. Call Run to start pumping packets.
func New(cfg Config) (*Stack, error) {
	if cfg.FD <= 0 {
		return nil, errors.New("vpn: tun fd required")
	}
	if cfg.Dial == nil {
		return nil, errors.New("vpn: dialer required")
	}
	if cfg.MTU == 0 {
		cfg.MTU = 8500
	}
	if cfg.Egress == "" {
		cfg.Egress = EgressDirect
	}
	dev := os.NewFile(uintptr(cfg.FD), "tun")
	if dev == nil {
		return nil, errors.New("vpn: bad tun fd")
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Stack{cfg: cfg, dev: dev, ctx: ctx, cancel: cancel}

	ep := channel.New(1024, cfg.MTU, "")
	s.ep = ep

	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	s.net = st

	const nicID = tcpip.NICID(1)
	if err := st.CreateNIC(nicID, ep); err != nil {
		cancel()
		return nil, fmt.Errorf("vpn: CreateNIC: %v", err)
	}
	// The stack must accept packets for arbitrary destinations (that is the
	// whole point of a tun2socks) and reply from them.
	if err := st.SetPromiscuousMode(nicID, true); err != nil {
		cancel()
		return nil, fmt.Errorf("vpn: promiscuous: %v", err)
	}
	if err := st.SetSpoofing(nicID, true); err != nil {
		cancel()
		return nil, fmt.Errorf("vpn: spoofing: %v", err)
	}

	// TUN-side addresses: the VPN subnet the device routes into us.
	v4 := tcpip.AddrFrom4([4]byte{10, 111, 0, 1}).WithPrefix()
	v6 := tcpip.AddrFrom16(mustULA()).WithPrefix()
	for _, pa := range []tcpip.ProtocolAddress{
		{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: v4},
		{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: v6},
	} {
		if err := st.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
			cancel()
			return nil, fmt.Errorf("vpn: AddProtocolAddress %s: %v", pa.AddressWithPrefix, err)
		}
	}
	st.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	tcpFwd := tcp.NewForwarder(st, 0, 65536, s.handleTCP)
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(st, func(r *udp.ForwarderRequest) (handled bool) {
		s.handleUDP(r)
		return true
	})
	st.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return s, nil
}

func mustULA() [16]byte {
	var a [16]byte
	a[0] = 0xfd
	a[1] = 0x00
	a[2] = 0x71 // 'q'
	a[3] = 0x75 // 'u'
	a[4] = 0x6c // 'l'
	a[5] = 0x6f // 'o'
	a[6] = 0x67 // 'g'
	a[7] = 0x69 // 'i'
	a[15] = 0x01
	return a
}

// Run starts the read/write pump goroutines.
func (s *Stack) Run() {
	s.wg.Add(2)
	go s.readLoop()
	go s.writeLoop()
	s.logf("vpn: netstack up (mtu=%d egress=%s)", s.cfg.MTU, s.cfg.Egress)
}

func (s *Stack) readLoop() {
	defer s.wg.Done()
	buf := make([]byte, s.cfg.MTU+128)
	for {
		n, err := s.dev.Read(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			s.logf("vpn: tun read: %v", err)
			return
		}
		if n < 20 {
			continue
		}
		proto := header.IPv4ProtocolNumber
		if buf[0]>>4 == 6 {
			proto = header.IPv6ProtocolNumber
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(append([]byte(nil), buf[:n]...)),
		})
		s.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

func (s *Stack) writeLoop() {
	defer s.wg.Done()
	for {
		pkt := s.ep.ReadContext(s.ctx)
		if pkt == nil {
			return
		}
		data := pkt.ToView().AsSlice()
		if _, err := s.dev.Write(data); err != nil {
			pkt.DecRef()
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			s.logf("vpn: tun write: %v", err)
			return
		}
		pkt.DecRef()
	}
}

// SetBlocked implements the kill switch: when enabled every new flow is
// refused (TCP reset, UDP dropped) until the tunnel is healthy again.
func (s *Stack) SetBlocked(b bool) {
	if s.blocked.Swap(b) != b {
		if b {
			s.logf("vpn: kill switch ON, blocking all flows")
		} else {
			s.logf("vpn: kill switch OFF")
		}
	}
}

// Stop tears the stack down and closes the TUN device.
func (s *Stack) Stop() {
	s.stopOnce.Do(func() {
		s.cancel()
		s.dev.Close()
		s.net.Close()
		s.wg.Wait()
		s.logf("vpn: netstack stopped")
	})
}

func (s *Stack) Snapshot() Status {
	return Status{
		Running: s.ctx.Err() == nil,
		Blocked: s.blocked.Load(),
		Flows:   s.flows.Load(),
		Up:      atomicOr(s.cfg.Up),
		Down:    atomicOr(s.cfg.Down),
		Egress:  s.cfg.Egress,
	}
}

func atomicOr(c *atomic.Int64) int64 {
	if c == nil {
		return 0
	}
	return c.Load()
}

func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	if s.blocked.Load() {
		r.Complete(true)
		return
	}
	wq := &waiter.Queue{}
	ep, err := r.CreateEndpoint(wq)
	if err != nil {
		r.Complete(true)
		return
	}
	client := gonet.NewTCPConn(wq, ep)

	up, derr := s.cfg.Dial(s.ctx, "tcp", dst)
	if derr != nil {
		s.logf("vpn: tcp %s: %v", dst, derr)
		client.Close()
		return
	}
	s.flows.Add(1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.flows.Add(-1)
		relayTCP(client, up, s.cfg.Up, s.cfg.Down)
	}()
}

func relayTCP(client, up net.Conn, upCount, downCount *atomic.Int64) {
	defer client.Close()
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(countWriter{up, upCount}, client)
		_ = n
		up.Close()
		client.Close()
		done <- struct{}{}
	}()
	io.Copy(countWriter{client, downCount}, up)
	client.Close()
	up.Close()
	<-done
}

type countWriter struct {
	w io.Writer
	c *atomic.Int64
}

func (cw countWriter) Write(p []byte) (int, error) {
	if cw.c != nil {
		cw.c.Add(int64(len(p)))
	}
	return cw.w.Write(p)
}

func (s *Stack) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dstPort := int(id.LocalPort)
	dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(dstPort))
	if s.blocked.Load() {
		return // silently drop
	}
	wq := &waiter.Queue{}
	ep, err := r.CreateEndpoint(wq)
	if err != nil {
		return
	}
	conn := gonet.NewUDPConn(wq, ep)

	switch {
	case dstPort == 53 && (s.cfg.Egress == EgressTunnel || s.cfg.Egress == EgressSplit):
		// DNS rides the tunnel over TCP: plain UDP answers can be spoofed
		// in the filtered network, and the relay resolves what the client
		// cannot.
		s.flows.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.flows.Add(-1)
			s.relayDNSOverTCP(conn, dst)
		}()
	case s.cfg.Egress == EgressTunnel:
		s.dnsOnce.Do(func() { s.logf("vpn: udp dropped in tunnel mode (only DNS is relayed)") })
		conn.Close()
	case s.cfg.Egress == EgressSplit:
		switch {
		case s.cfg.UDPRoute != nil && s.cfg.UDPRoute(id.LocalAddress.String(), dstPort) == "direct":
			up, derr := s.cfg.Dial(s.ctx, "udp", dst)
			if derr != nil {
				conn.Close()
				return
			}
			s.flows.Add(1)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer s.flows.Add(-1)
				relayUDP(conn, up)
			}()
		default:
			// QUIC and friends: a silent drop pushes browsers onto
			// TCP/TLS, which the tunnel carries.
			s.dnsOnce.Do(func() { s.logf("vpn: non-whitelisted udp dropped in split mode") })
			conn.Close()
		}
	default:
		up, derr := s.cfg.Dial(s.ctx, "udp", dst)
		if derr != nil {
			conn.Close()
			return
		}
		s.flows.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.flows.Add(-1)
			relayUDP(conn, up)
		}()
	}
}

func relayUDP(conn *gonet.UDPConn, up net.Conn) {
	defer up.Close()
	defer conn.Close()
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if _, werr := up.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := up.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done
}

// relayDNSOverTCP answers DNS queries arriving as UDP datagrams by
// exchanging them over TCP through the tunnel dialer. Every serious
// resolver speaks DNS over TCP (RFC 7766), so no functionality is lost
// while the tunnel transport stays TCP-only.
func (s *Stack) relayDNSOverTCP(conn *gonet.UDPConn, dst string) {
	defer conn.Close()
	buf := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		resp, err := s.dnsOverTCP(dst, buf[:n])
		if err != nil {
			s.logf("vpn: dns over tcp: %v", err)
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(resp); err != nil {
			return
		}
	}
}

func (s *Stack) dnsOverTCP(dst string, query []byte) ([]byte, error) {
	c, err := s.cfg.Dial(s.ctx, "tcp", dst)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	msg := make([]byte, 0, len(query)+2)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(query)))
	msg = append(msg, l[:]...)
	msg = append(msg, query...)
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n == 0 {
		return nil, errors.New("vpn: empty dns response")
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *Stack) logf(format string, args ...any) {
	if s.cfg.Log != nil {
		s.cfg.Log(fmt.Sprintf(format, args...))
	}
}
