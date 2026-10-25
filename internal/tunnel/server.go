package tunnel

import (
        "errors"
        "fmt"
        "io"
        "net"
        "time"

        "github.com/mel0k1/qulogi/internal/transport"
)

type Server struct {
        Listener net.Listener
        PSK      []byte
        Log      func(string)
}

func (s *Server) Serve() error {
        for {
                conn, err := s.Listener.Accept()
                if err != nil {
                        var ne net.Error
                        if errors.As(err, &ne) && ne.Timeout() {
                                continue
                        }
                        return err
                }
                go s.handle(conn)
        }
}

func (s *Server) handle(conn net.Conn) {
        defer conn.Close()
        wrapped, camo, err := transport.WrapServer(conn)
        if err != nil {
                s.logf("probe %s: %v", conn.RemoteAddr(), err)
                return
        }
        if camo {
                s.logf("camo handshake from %s", conn.RemoteAddr())
        }
        sk, err := serverHandshake(wrapped, s.PSK)
        if err != nil {
                s.logf("reject %s", conn.RemoteAddr())
                return
        }
        target, err := ReadAddress(sk)
        if err != nil {
                return
        }
        up, err := net.DialTimeout("tcp", target.String(), 10*time.Second)
        if err != nil {
                s.logf("dial %s: %v", target.String(), err)
                return
        }
        defer up.Close()
        s.logf("open %s", target.String())
        relay(sk, up)
        s.logf("close %s", target.String())
}

func relay(a, b net.Conn) {
        go func() {
                io.Copy(a, b)
                b.Close()
        }()
        io.Copy(b, a)
        a.Close()
}

func (s *Server) logf(format string, args ...any) {
        if s.Log != nil {
                s.Log(fmt.Sprintf(format, args...))
        }
}
