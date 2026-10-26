package turnrelay

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Server is a minimal RFC 5766 + RFC 6062 TURN server over TCP. It
// understands exactly what the client needs — Allocate (with or without
// long-term credentials), Refresh, CreatePermission, Connect and
// ConnectionBind — and splices bound data connections to the peer. It is
// intended for the test suite, the smoke pipeline and community relays
// (cmd/qulogiturn); production deployments can point the client at any
// RFC 6062-capable server such as coturn.
type Server struct {
	Listener net.Listener
	// User, Realm and Pass enable long-term credentials. Empty user
	// means anonymous.
	User  string
	Realm string
	Pass  string
	// Lifetime is the allocation window reported to clients (default 10
	// minutes; shrink it in tests).
	Lifetime time.Duration
	// DialPeer opens the peer connection for Connect. Defaults to a
	// 5-second net.DialTimeout.
	DialPeer func(network, addr string) (net.Conn, error)
	// Log receives one line per event.
	Log func(string)

	mu      sync.Mutex
	pending map[uint32]net.Conn // connection id → peer conn waiting for the bind
	closed  bool
	wg      sync.WaitGroup
}

func (s *Server) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log(fmt.Sprintf(format, args...))
	}
}

// Serve accepts clients until the listener is closed.
func (s *Server) Serve() error {
	if s.pending == nil {
		s.pending = map[uint32]net.Conn{}
	}
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			if s.closed {
				return nil
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

// Close stops accepting; open sessions drain on their own.
func (s *Server) Close() error {
	s.closed = true
	return s.Listener.Close()
}

// Wait blocks until every accepted handler returned (tests use it to
// avoid leaked goroutines).
func (s *Server) Wait() { s.wg.Wait() }

type allocation struct {
	key      []byte
	realm    string
	nonce    string
	lifetime time.Duration
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	var alloc *allocation
	for {
		msg, raw, err := readMessageRaw(conn, time.Now().Add(30*time.Second))
		if err != nil {
			return
		}
		if msg.Class != classRequest {
			return // nothing else is expected on this transport
		}
		switch msg.Method {
		case methodAllocate:
			alloc, err = s.onAllocate(conn, msg, raw)
		case methodRefresh:
			err = s.onRefresh(conn, msg, raw, alloc)
		case methodCreatePermissi:
			err = s.reply(conn, msg, raw, alloc, 0, "")
		case methodConnect:
			err = s.onConnect(conn, msg, raw, alloc)
		case methodConnectionBind:
			err = s.onConnectionBind(conn, msg, raw, alloc)
		default:
			err = s.reply(conn, msg, raw, alloc, 400, "Bad Request")
		}
		if err != nil {
			s.logf("turn-server: %v", err)
			return
		}
	}
}

// onAllocate processes the allocation, answering 401 with realm/nonce
// when credentials are configured and the request is not authenticated.
func (s *Server) onAllocate(conn net.Conn, msg *Message, raw []byte) (*allocation, error) {
	if v := msg.Get(attrReqTransport); len(v) != 4 || v[0] != protoUDP {
		return nil, s.reply(conn, msg, raw, nil, 442, "Unsupported Transport Protocol")
	}
	st := &allocation{realm: s.Realm, lifetime: s.Lifetime}
	if st.lifetime <= 0 {
		st.lifetime = 600 * time.Second
	}
	if s.User != "" {
		user := string(msg.Get(attrUsername))
		if user != s.User || !VerifyMessageIntegrity(raw, LongTermKey(user, s.Realm, s.Pass)) {
			nonce := make([]byte, 8)
			_, _ = rand.Read(nonce)
			st.nonce = hex.EncodeToString(nonce)
			chal := s.response(msg, classError, nil)
			chal.Add(attrErrorCode, errCodeValue(401, "Unauthorized"))
			chal.Add(attrRealm, []byte(s.Realm))
			chal.Add(attrNonce, []byte(st.nonce))
			if _, err := conn.Write(chal.Encode(nil, false)); err != nil {
				return nil, err
			}
			return nil, nil // continue on the same connection: retry expected
		}
		st.key = LongTermKey(user, s.Realm, s.Pass)
	}
	resp := s.response(msg, classSuccess, st)
	if v, xerr := resp.encodeXORAddr(conn.LocalAddr().String()); xerr == nil {
		resp.Add(attrXORRelayedAddr, v)
	}
	resp.Add(attrLifetime, binary.BigEndian.AppendUint32(nil, uint32(st.lifetime/time.Second)))
	if _, err := conn.Write(resp.Encode(st.key, false)); err != nil {
		return nil, err
	}
	s.logf("turn-server: allocated for %s", userOf(msg))
	return st, nil
}

func (s *Server) onRefresh(conn net.Conn, msg *Message, raw []byte, alloc *allocation) error {
	if !s.authorized(conn, msg, raw, alloc) {
		return nil
	}
	return s.reply(conn, msg, raw, alloc, 0, "")
}

func (s *Server) onConnect(conn net.Conn, msg *Message, raw []byte, alloc *allocation) error {
	if !s.authorized(conn, msg, raw, alloc) {
		return nil
	}
	av := msg.Get(attrXORPeerAddress)
	if av == nil {
		return s.reply(conn, msg, raw, alloc, 400, "Bad Request")
	}
	peer, err := msg.PeerAddress(av)
	if err != nil {
		return s.reply(conn, msg, raw, alloc, 400, "Bad Request")
	}
	dial := s.DialPeer
	if dial == nil {
		dial = func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, 5*time.Second)
		}
	}
	pc, pdial := dial("tcp", peer)
	if pdial != nil {
		s.logf("turn-server: connect to %s: %v", peer, pdial)
		return s.reply(conn, msg, raw, alloc, 447, "Connection Timeout or Failure")
	}
	var idb [4]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint32(idb[:])
	s.mu.Lock()
	s.pending[id] = pc
	s.mu.Unlock()
	resp := s.response(msg, classSuccess, alloc)
	resp.Add(attrConnectionID, idb[:])
	if _, werr := conn.Write(resp.Encode(allocKey(alloc), false)); werr != nil {
		pc.Close()
		return werr
	}
	s.logf("turn-server: connect #%d to %s, waiting for bind", id, peer)
	return nil
}

// onConnectionBind splices the freshly bound data connection with the
// peer connection reserved by Connect.
func (s *Server) onConnectionBind(conn net.Conn, msg *Message, raw []byte, alloc *allocation) error {
	if !s.authorized(conn, msg, raw, alloc) {
		return nil
	}
	v := msg.Get(attrConnectionID)
	if len(v) != 4 {
		return s.reply(conn, msg, raw, alloc, 400, "Bad Request")
	}
	id := binary.BigEndian.Uint32(v)
	s.mu.Lock()
	pc, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	}
	s.mu.Unlock()
	if !ok {
		return s.reply(conn, msg, raw, alloc, 400, "Unknown Connection ID")
	}
	if rerr := s.reply(conn, msg, raw, alloc, 0, ""); rerr != nil {
		pc.Close()
		return rerr
	}
	// Raw data from here on: splice both directions.
	s.logf("turn-server: bind #%d established", id)
	go func() {
		_, _ = io.Copy(pc, conn)
		pc.Close()
		conn.Close()
	}()
	_, _ = io.Copy(conn, pc)
	pc.Close()
	conn.Close()
	return nil
}

// authorized answers 401 when the request is not properly authenticated
// and reports false when the exchange ended with an error reply.
// Authentication is checked against the static server configuration, so
// requests on the second (data) connection — which carries no allocation
// state — are verified the same way (RFC 6062 §4.2.2).
func (s *Server) authorized(conn net.Conn, msg *Message, raw []byte, alloc *allocation) bool {
	if s.User == "" {
		return true // anonymous server: everything is accepted
	}
	user := string(msg.Get(attrUsername))
	if user != s.User || !VerifyMessageIntegrity(raw, LongTermKey(user, s.Realm, s.Pass)) {
		_ = s.reply(conn, msg, raw, alloc, 401, "Unauthorized")
		return false
	}
	return true
}

// reply sends a success (code 0) or error response.
func (s *Server) reply(conn net.Conn, msg *Message, raw []byte, alloc *allocation, code int, reason string) error {
	resp := s.response(msg, classSuccess, alloc)
	if code != 0 {
		resp = s.response(msg, classError, alloc)
		resp.Add(attrErrorCode, errCodeValue(code, reason))
	}
	_, err := conn.Write(resp.Encode(allocKey(alloc), false))
	return err
}

// response builds a response frame with the request transaction id.
func (s *Server) response(req *Message, class int, alloc *allocation) *Message {
	resp := NewMessage(req.Method, class)
	resp.Transaction = req.Transaction
	if alloc != nil && alloc.nonce != "" {
		resp.Add(attrNonce, []byte(alloc.nonce))
	}
	if s.Realm != "" {
		resp.Add(attrRealm, []byte(s.Realm))
	}
	return resp
}

func allocKey(a *allocation) []byte {
	if a == nil {
		return nil
	}
	return a.key
}

func userOf(msg *Message) string {
	if u := msg.Get(attrUsername); u != nil {
		return string(u)
	}
	return "(anonymous)"
}
