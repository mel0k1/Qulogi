// Directory fetching over mirrors: plain HTTPS, DNS TXT (a tiny hand-rolled
// wire-format client, so it works on every platform without cgo) and
// DNS-over-HTTPS. All sources race concurrently; the first document whose
// signature checks out wins. A local cache of the last good directory
// provides a fallback for the moments when every mirror is unreachable.
package discover

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Source is one mirror of the directory.
type Source struct {
	// Type: "https" (URL is a catalog URL), "dns-txt" (Name is queried for
	// TXT records at Server) or "doh" (TXT over the DoH endpoint in URL).
	Type string `json:"type"`
	// URL is used by https and doh sources.
	URL string `json:"url,omitempty"`
	// Name is the DNS name queried by dns-txt and doh sources.
	Name string `json:"name,omitempty"`
	// Server is the UDP DNS server "ip:port" for dns-txt sources. Empty
	// means port 53 on the address given in Name's server field... the
	// caller should always set it explicitly for dns-txt.
	Server string `json:"server,omitempty"`
}

// Display renders the source for logs and UI lists.
func (s Source) Display() string {
	switch s.Type {
	case "https":
		return "https:" + s.URL
	case "doh":
		return "doh:" + s.Name + "@" + s.URL
	default:
		return "dns-txt:" + s.Name + "@" + s.Server
	}
}

// DefaultSources are the mirrors wired into the build. They point at the
// community catalog repository; operators replace or extend this list via
// app settings. The DNS names are placeholders until a community zone
// exists — failures are non-fatal, other mirrors still answer.
func DefaultSources() []Source {
	return []Source{
		{Type: "https", URL: "https://raw.githubusercontent.com/mel0k1/qulogi-catalog/main/catalog.json"},
		{Type: "https", URL: "https://cdn.jsdelivr.net/gh/mel0k1/qulogi-catalog@main/catalog.json"},
		{Type: "dns-txt", Name: "_qulogi.qulogi.example.org", Server: "77.88.8.8:53"},
		{Type: "dns-txt", Name: "_qulogi.qulogi.example.org", Server: "8.8.8.8:53"},
		{Type: "doh", Name: "_qulogi.qulogi.example.org", URL: "https://dns.google/dns-query"},
	}
}

// Result is a fetched and verified directory plus its provenance.
type Result struct {
	Directory *Directory
	Source    string
	// Verified is true when the signature matched a pinned key. Unsigned
	// catalogs are only accepted when no key was supplied.
	Verified bool
}

// Fetch races every source concurrently and returns the first directory
// that passes verification. pub may be nil (tests, local catalogs): the
// signature is then not required, only structural validation runs and
// Result.Verified stays false. httpc is used for https and doh sources;
// nil means a client with sane timeouts.
func Fetch(ctx context.Context, srcs []Source, pub ed25519.PublicKey, httpc *http.Client) (*Result, error) {
	if len(srcs) == 0 {
		srcs = DefaultSources()
	}
	if httpc == nil {
		httpc = &http.Client{Timeout: 10 * time.Second}
	}
	type attempt struct {
		src  string
		dir  *Directory
		err  error
		verb bool
	}
	out := make(chan attempt, len(srcs))
	for _, s := range srcs {
		go func(s Source) {
			dir, err := fetchOne(ctx, s, httpc)
			if err == nil {
				err = checkDir(dir, pub)
			}
			out <- attempt{src: s.Display(), dir: dir, err: err, verb: pub != nil}
		}(s)
	}
	var failures []string
	for range srcs {
		a := <-out
		if a.err == nil {
			return &Result{Directory: a.dir, Source: a.src, Verified: a.verb}, nil
		}
		failures = append(failures, a.src+": "+a.err.Error())
	}
	return nil, fmt.Errorf("discover: all mirrors failed: %s", strings.Join(failures, "; "))
}

// checkDir verifies the signature (when a key is pinned) and structure.
func checkDir(d *Directory, pub ed25519.PublicKey) error {
	if d == nil {
		return errors.New("empty directory")
	}
	if err := d.Validate(); err != nil {
		return err
	}
	if pub != nil {
		return d.Verify(pub, time.Now())
	}
	return nil
}

func fetchOne(ctx context.Context, s Source, httpc *http.Client) (*Directory, error) {
	switch s.Type {
	case "https":
		return fetchHTTP(ctx, s.URL, httpc)
	case "dns-txt":
		lines, err := txtUDP(s.Server, s.Name, 5*time.Second)
		if err != nil {
			return nil, err
		}
		return fromTXT(ctx, lines, httpc)
	case "doh":
		lines, err := txtDoH(s.URL, s.Name, httpc)
		if err != nil {
			return nil, err
		}
		return fromTXT(ctx, lines, httpc)
	default:
		return nil, fmt.Errorf("discover: unknown source type %q", s.Type)
	}
}

func fetchHTTP(ctx context.Context, url string, httpc *http.Client) (*Directory, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Qulogi/0.3 (+https://github.com/mel0k1/Qulogi)")
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var d Directory
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("bad json: %w", err)
	}
	return &d, nil
}

// fromTXT assembles a TXT payload and either fetches the mirror URL it
// points to or decodes the chunked catalog body.
func fromTXT(ctx context.Context, lines []string, httpc *http.Client) (*Directory, error) {
	payload, err := assembleTXT(lines)
	if err != nil {
		return nil, err
	}
	if s := string(payload); strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return fetchHTTP(ctx, s, httpc)
	}
	var d Directory
	if err := json.Unmarshal(payload, &d); err != nil {
		return nil, fmt.Errorf("bad json: %w", err)
	}
	return &d, nil
}

// assembleTXT joins TXT strings into one payload. The pointer form is a
// single "https://…" string. The chunked form is base64: every string
// carries a two-hex-digit order prefix ("00", "01", …) so the receiver can
// rebuild the document regardless of answer order.
func assembleTXT(lines []string) ([]byte, error) {
	var payload []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			payload = append(payload, l)
		}
	}
	if len(payload) == 0 {
		return nil, errors.New("discover: empty TXT answer")
	}
	if strings.HasPrefix(payload[0], "http://") || strings.HasPrefix(payload[0], "https://") {
		return []byte(payload[0]), nil
	}
	sort.Slice(payload, func(i, j int) bool { return payload[i] < payload[j] })
	var b strings.Builder
	for i, l := range payload {
		if len(l) < 2 {
			return nil, fmt.Errorf("discover: TXT chunk %d too short", i)
		}
		b.WriteString(l[2:])
	}
	raw, err := base64.StdEncoding.DecodeString(b.String())
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(b.String()); err != nil {
			return nil, fmt.Errorf("discover: TXT base64: %w", err)
		}
	}
	return raw, nil
}

// --- minimal DNS wire format (UDP) ---

// txtUDP asks server for the TXT records of name and returns every string
// from every answer record. A 2-byte query id makes the exchange
// identifiable; responses with a foreign id are ignored.
func txtUDP(server, name string, timeout time.Duration) ([]string, error) {
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}
	query := dnsQuery(name)
	raddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 2 || binary.BigEndian.Uint16(buf[:2]) != binary.BigEndian.Uint16(query[:2]) {
			continue // foreign id, wait for ours
		}
		return parseTXT(buf[:n])
	}
}

// txtDoH asks a DNS-over-HTTPS endpoint (RFC 8484, wire format POST).
func txtDoH(endpoint, name string, httpc *http.Client) ([]string, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(dnsQuery(name))))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	return parseTXT(body)
}

// dnsQuery builds a recursive TXT query for name.
func dnsQuery(name string) []byte {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	msg := []byte{0x1f, 0x2f, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0, 0, 16, 0, 1) // root, TXT, IN
	return msg
}

// parseTXT extracts all TXT strings from a DNS response, following
// compression pointers in record names as needed.
func parseTXT(msg []byte) ([]string, error) {
	if len(msg) < 12 {
		return nil, errors.New("discover: short dns answer")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x000F != 0 {
		return nil, fmt.Errorf("discover: dns rcode %d", flags&0x000F)
	}
	off := 12
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	for i := 0; i < qd && off < len(msg); i++ {
		next, err := skipName(msg, off)
		if err != nil {
			return nil, err
		}
		off = next + 4 // QTYPE + QCLASS
	}
	var out []string
	for i := 0; i < an && off+10 <= len(msg); i++ {
		o, err := skipName(msg, off)
		if err != nil {
			return nil, err
		}
		typ := binary.BigEndian.Uint16(msg[o : o+2])
		rdlen := int(binary.BigEndian.Uint16(msg[o+8 : o+10]))
		rd := msg[o+10:]
		if len(rd) < rdlen {
			return nil, errors.New("discover: truncated dns answer")
		}
		if typ == 16 { // TXT
			out = append(out, txtStrings(rd[:rdlen])...)
		}
		off = o + 10 + rdlen
	}
	if len(out) == 0 {
		return nil, errors.New("discover: no TXT records")
	}
	return out, nil
}

func txtStrings(rdata []byte) []string {
	var out []string
	for len(rdata) > 0 {
		n := int(rdata[0])
		if 1+n > len(rdata) {
			break
		}
		out = append(out, string(rdata[1:1+n]))
		rdata = rdata[1+n:]
	}
	return out
}

// skipName walks (or jumps over) a possibly compressed domain name and
// returns the offset right after it.
func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errors.New("discover: truncated dns name")
		}
		n := int(msg[off])
		switch n & 0xC0 {
		case 0x00:
			if n == 0 {
				return off + 1, nil
			}
			off += 1 + n
		case 0xC0:
			if off+2 > len(msg) {
				return 0, errors.New("discover: bad dns pointer")
			}
			return off + 2, nil
		default:
			return 0, errors.New("discover: unsupported dns label")
		}
	}
}

// --- last good directory cache ---

// Cache is the persisted copy of the last successfully fetched directory.
type Cache struct {
	Directory *Directory `json:"directory"`
	Source    string     `json:"source"`
	SavedAt   time.Time  `json:"saved_at"`
}

// SaveCache writes the cache file (pretty-printed for debuggability).
func SaveCache(path string, d *Directory, source string) error {
	if path == "" {
		return nil
	}
	b, err := json.MarshalIndent(Cache{Directory: d, Source: source, SavedAt: time.Now().UTC()}, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, b)
}

// LoadCache reads the cache file. A missing file is not an error.
func LoadCache(path string) (*Cache, error) {
	if path == "" {
		return nil, nil
	}
	b, err := readFile(path)
	if err != nil {
		if errors.Is(err, errNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var c Cache
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
