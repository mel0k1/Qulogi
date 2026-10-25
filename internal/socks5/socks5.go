package socks5

import (
        "context"
        "encoding/binary"
        "errors"
        "fmt"
        "io"
        "net"
        "strconv"
        "time"
)

const (
        ver5     = 5
        authNone = 0
        cmdConn  = 1

        atypIPv4   = 1
        atypDomain = 3
        atypIPv6   = 4
)

type Pump func(client, upstream net.Conn) error

type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type Server struct {
        Listener net.Listener
        Dial     DialFunc
        Pump     Pump
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

func (s *Server) handle(client net.Conn) {
        defer client.Close()
        if err := s.connect(client); err != nil {
                s.logf("%s: %v", client.RemoteAddr(), err)
        }
}

func (s *Server) connect(client net.Conn) error {
        var head [2]byte
        if _, err := io.ReadFull(client, head[:]); err != nil {
                return err
        }
        if head[0] != ver5 {
                return errors.New("socks5: unsupported version")
        }
        methods := make([]byte, head[1])
        if _, err := io.ReadFull(client, methods); err != nil {
                return err
        }
        offered := false
        for _, m := range methods {
                if m == authNone {
                        offered = true
                }
        }
        if !offered {
                client.Write([]byte{ver5, 0xFF})
                return errors.New("socks5: no acceptable auth method")
        }
        if _, err := client.Write([]byte{ver5, authNone}); err != nil {
                return err
        }

        var req [4]byte
        if _, err := io.ReadFull(client, req[:]); err != nil {
                return err
        }
        if req[0] != ver5 {
                return errors.New("socks5: unsupported request version")
        }
        if req[1] != cmdConn {
                s.reply(client, 7)
                return errors.New("socks5: only CONNECT supported")
        }

        var host string
        switch req[3] {
        case atypIPv4:
                var raw [4]byte
                if _, err := io.ReadFull(client, raw[:]); err != nil {
                        return err
                }
                host = net.IP(raw[:]).String()
        case atypDomain:
                var l [1]byte
                if _, err := io.ReadFull(client, l[:]); err != nil {
                        return err
                }
                raw := make([]byte, l[0])
                if _, err := io.ReadFull(client, raw); err != nil {
                        return err
                }
                host = string(raw)
        case atypIPv6:
                var raw [16]byte
                if _, err := io.ReadFull(client, raw[:]); err != nil {
                        return err
                }
                host = net.IP(raw[:]).String()
        default:
                s.reply(client, 8)
                return errors.New("socks5: bad address type")
        }
        var portb [2]byte
        if _, err := io.ReadFull(client, portb[:]); err != nil {
                return err
        }
        port := binary.BigEndian.Uint16(portb[:])
        target := net.JoinHostPort(host, strconv.Itoa(int(port)))

        dial := s.Dial
        if dial == nil {
                dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
                        d := &net.Dialer{Timeout: 10 * time.Second}
                        return d.DialContext(ctx, network, addr)
                }
        }
        up, err := dial(context.Background(), "tcp", target)
        if err != nil {
                s.reply(client, 5)
                return fmt.Errorf("dial %s: %w", target, err)
        }
        defer up.Close()

        if err := s.reply(client, 0); err != nil {
                return err
        }
        pump := s.Pump
        if pump == nil {
                pump = DefaultPump
        }
        return pump(client, up)
}

func (s *Server) reply(client net.Conn, code byte) error {
        _, err := client.Write([]byte{ver5, code, 0, 1, 0, 0, 0, 0, 0, 0})
        return err
}

func DefaultPump(client, upstream net.Conn) error {
        errc := make(chan error, 2)
        go func() {
                _, err := io.Copy(client, upstream)
                errc <- err
        }()
        go func() {
                _, err := io.Copy(upstream, client)
                errc <- err
        }()
        err := <-errc
        client.Close()
        upstream.Close()
        <-errc
        return err
}

func (s *Server) logf(format string, args ...any) {
        if s.Log != nil {
                s.Log(fmt.Sprintf(format, args...))
        }
}
