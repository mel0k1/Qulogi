// Package dpi implements connection-level desynchronization tricks in the
// spirit of zapret/goodbye-dpi: TLS ClientHello segmentation with optional
// extra splits and segment pacing. All of them are transparent for the
// remote server (the byte stream is unchanged) and require no privileges.
package dpi

import (
        "encoding/binary"
        "io"
        "net"
        "sort"
        "time"
)

const maxFirstRead = 32 * 1024

// Strategy configures how the first data segment of a proxied connection is
// chopped before it leaves for the remote server.
type Strategy struct {
        // Split is the size of the first chunk: 0 means "auto" (right after
        // the SNI hostname), N splits after N bytes, -1 disables splitting.
        Split int
        // Multi adds a second split deep inside the ClientHello so DPI
        // reassembly engines have to buffer several tiny segments.
        Multi bool
        // Delay pauses between the first and the following segments, forcing
        // them out as separate TCP packets even without Nagle.
        Delay time.Duration
}

// Default is the sane starting point: one split right after the SNI.
var Default = Strategy{Split: 0}

// None disables every desync trick.
var None = Strategy{Split: -1}

// Pump returns a bidirectional relay that applies the strategy to the first
// client-to-upstream segment. Suitable for socks5.Server Pump field.
func Pump(s Strategy) func(client, upstream net.Conn) error {
        return func(client, upstream net.Conn) error {
                if tc, ok := upstream.(*net.TCPConn); ok {
                        _ = tc.SetNoDelay(true)
                }
                errc := make(chan error, 2)
                go func() {
                        _, err := io.Copy(client, upstream)
                        errc <- err
                }()
                go func() {
                        errc <- copySplit(upstream, client, s)
                }()
                err := <-errc
                client.Close()
                upstream.Close()
                <-errc
                return err
        }
}

func copySplit(upstream, client net.Conn, s Strategy) error {
        buf := make([]byte, maxFirstRead)
        n, err := client.Read(buf)
        if n > 0 {
                parts := fragments(buf[:n], s)
                for i, part := range parts {
                        if i == 1 && s.Delay > 0 {
                                time.Sleep(s.Delay)
                        }
                        if _, werr := upstream.Write(part); werr != nil {
                                return werr
                        }
                }
        }
        if err != nil {
                if err == io.EOF {
                        return nil
                }
                return err
        }
        _, err = io.Copy(upstream, client)
        return err
}

// fragments computes the segment boundaries for the first data burst.
func fragments(data []byte, s Strategy) [][]byte {
        if len(data) == 0 || s.Split < 0 {
                return [][]byte{data}
        }
        sniPos := -1
        if data[0] == 0x16 {
                sniPos = clientHelloSplit(data)
        }

        first := -1
        switch {
        case s.Split > 0:
                first = min(s.Split, len(data))
        case sniPos > 0:
                first = sniPos
        case data[0] == 0x16:
                first = 1
        default:
                return [][]byte{data}
        }
        if first <= 0 || first >= len(data) {
                return [][]byte{data}
        }

        bounds := []int{first}
        if s.Multi {
                second := -1
                switch {
                case sniPos > first+3 && sniPos < len(data):
                        second = sniPos // extra cut right at the SNI boundary
                case first > 8:
                        second = first - 8 // extra cut deep inside the hostname
                case len(data) > first+8:
                        second = first + (len(data)-first)/2
                }
                if second > 0 {
                        bounds = append(bounds, second)
                }
        }
        sort.Ints(bounds)

        parts := make([][]byte, 0, len(bounds)+1)
        prev := 0
        for _, b := range bounds {
                if b > prev && b < len(data) {
                        parts = append(parts, data[prev:b])
                        prev = b
                }
        }
        parts = append(parts, data[prev:])
        return parts
}

func clientHelloSplit(data []byte) int {
        if len(data) < 48 {
                return -1
        }
        if data[0] != 0x16 || data[1] != 3 {
                return -1
        }
        if data[5] != 1 {
                return -1
        }
        recLen := int(binary.BigEndian.Uint16(data[3:5]))
        if 5+recLen > len(data) {
                return -1
        }
        end := 5 + recLen
        p := 9 + 32
        if p+1 > end {
                return -1
        }
        sidLen := int(data[p])
        p += 1 + sidLen
        if p+2 > end {
                return -1
        }
        csLen := int(binary.BigEndian.Uint16(data[p:]))
        p += 2 + csLen
        if p+1 > end {
                return -1
        }
        compLen := int(data[p])
        p += 1 + compLen
        if p+2 > end {
                return -1
        }
        extTotal := int(binary.BigEndian.Uint16(data[p:]))
        p += 2
        extEnd := min(p+extTotal, end)
        for p+4 <= extEnd {
                typ := binary.BigEndian.Uint16(data[p:])
                ln := int(binary.BigEndian.Uint16(data[p+2:]))
                body := p + 4
                if body+ln > extEnd {
                        return -1
                }
                if typ == 0 && ln >= 5 {
                        nameLen := int(binary.BigEndian.Uint16(data[body+3:]))
                        pos := body + 5 + nameLen
                        if pos > 0 && pos < len(data) {
                                return pos
                        }
                        return -1
                }
                p = body + ln
        }
        return -1
}
