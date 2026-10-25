package discover

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func signedDir(t *testing.T) (*Directory, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	d := &Directory{
		Updated: time.Now().UTC().Truncate(time.Second),
		TTLMin:  60,
		Relays: []Relay{{
			ID:     "owl-eu-1",
			Region: "eu-central",
			Weight: 60,
			Transports: []Transport{
				{Type: "qulogi-tls", Addr: "r1.example.net:443", SNI: "vkvideo.ru"},
			},
		}},
	}
	if err := d.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return d, pub
}

func TestFetchHTTPS(t *testing.T) {
	d, pub := signedDir(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d)
	}))
	defer srv.Close()

	res, err := Fetch(context.Background(), []Source{{Type: "https", URL: srv.URL}}, pub, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified || res.Directory.Relays[0].ID != "owl-eu-1" {
		t.Fatalf("bad result: %+v", res)
	}
}

func TestFetchRejectsBadSignature(t *testing.T) {
	d, pub := signedDir(t)
	d.Sig = base64.RawStdEncoding.EncodeToString(make([]byte, 64)) // garbage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(d)
	}))
	defer srv.Close()

	if _, err := Fetch(context.Background(), []Source{{Type: "https", URL: srv.URL}}, pub, srv.Client()); err == nil {
		t.Fatal("expected signature failure")
	}
}

func TestFetchFirstGoodWins(t *testing.T) {
	d, pub := signedDir(t)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(d)
	}))
	defer good.Close()

	srcs := []Source{
		{Type: "https", URL: bad.URL},
		{Type: "https", URL: good.URL},
	}
	res, err := Fetch(context.Background(), srcs, pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.Source, "https:"+good.URL) {
		t.Fatalf("expected good mirror, got %s", res.Source)
	}
}

// fakeDNSServer answers TXT queries for one name with the given strings
// (each becomes its own TXT record with one ≤255-byte string).
func fakeDNSServer(t *testing.T, name string, records [][]string) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !queryAsks(buf[:n], name) {
				continue
			}
			resp := buildTXTReply(buf[:n], records)
			_, _ = conn.WriteToUDP(resp, from)
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr)
}

func queryAsks(msg []byte, name string) bool {
	// crude check: decoded question name must contain the lowercase name
	off := 12
	var b strings.Builder
	for off < len(msg) {
		n := int(msg[off])
		if n == 0 || n&0xC0 != 0 {
			break
		}
		off++
		b.Write(msg[off : off+n])
		b.WriteByte('.')
		off += n
	}
	return strings.HasPrefix(b.String(), strings.ToLower(name))
}

func buildTXTReply(query []byte, records [][]string) []byte {
	msg := append([]byte(nil), query[:2]...)    // echo id
	msg = append(msg, 0x84, 0x00)               // response, rd
	msg = binary.BigEndian.AppendUint16(msg, 1) // question count
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(records)))
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	// question copy: echo everything after the 12-byte header
	msg = append(msg, query[12:]...)
	for _, strs := range records {
		msg = append(msg, 0xC0, 0x0C) // pointer to question name
		msg = binary.BigEndian.AppendUint16(msg, 16)
		msg = binary.BigEndian.AppendUint16(msg, 1)
		msg = binary.BigEndian.AppendUint32(msg, 60)
		var rdata []byte
		for _, s := range strs {
			rdata = append(rdata, byte(len(s)))
			rdata = append(rdata, s...)
		}
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
		msg = append(msg, rdata...)
	}
	return msg
}

func TestTXTChunks(t *testing.T) {
	d, pub := signedDir(t)
	body, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(body)
	var chunks []string
	for i := 0; i < len(b64); i += 200 {
		end := i + 200
		if end > len(b64) {
			end = len(b64)
		}
		chunks = append(chunks, fmt.Sprintf("%02x%s", len(chunks), b64[i:end]))
	}
	addr := fakeDNSServer(t, "_qulogi.test.", [][]string{chunks})

	res, err := Fetch(context.Background(),
		[]Source{{Type: "dns-txt", Name: "_qulogi.test", Server: addr.String()}}, pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Directory.Relays[0].ID != "owl-eu-1" {
		t.Fatalf("bad directory from TXT: %+v", res.Directory)
	}
}

func TestTXTPointer(t *testing.T) {
	d, pub := signedDir(t)
	catalog := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(d)
	}))
	defer catalog.Close()
	addr := fakeDNSServer(t, "_qulogi.test.", [][]string{{catalog.URL}})

	res, err := Fetch(context.Background(),
		[]Source{{Type: "dns-txt", Name: "_qulogi.test", Server: addr.String()}}, pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Directory.Relays[0].ID != "owl-eu-1" {
		t.Fatalf("bad directory via TXT pointer: %+v", res.Directory)
	}
}

func TestAssembleTXT(t *testing.T) {
	// pointer
	p, err := assembleTXT([]string{"https://example.org/catalog.json"})
	if err != nil || string(p) != "https://example.org/catalog.json" {
		t.Fatalf("pointer: %s %v", p, err)
	}
	// chunks out of order (payload long enough to split)
	raw := base64.StdEncoding.EncodeToString([]byte("Qulogi TXT chunk assembly test payload"))
	mid := len(raw) / 2
	got, err := assembleTXT([]string{"01" + raw[mid:], "00" + raw[:mid]})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "Qulogi TXT chunk assembly test payload" {
		t.Fatalf("chunks: %q", got)
	}
}

func TestCache(t *testing.T) {
	d, pub := signedDir(t)
	path := t.TempDir() + "/cache.json"
	if err := SaveCache(path, d, "https:mirror"); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Source != "https:mirror" || c.Directory.Relays[0].ID != "owl-eu-1" {
		t.Fatalf("bad cache: %+v", c)
	}
	if err := checkDir(c.Directory, pub); err != nil {
		t.Fatalf("cached directory must stay verifiable: %v", err)
	}
	if c2, _ := LoadCache(t.TempDir() + "/missing.json"); c2 != nil {
		t.Fatal("missing cache should be nil,nil")
	}
}

func TestInvites(t *testing.T) {
	tr := Transport{Type: "qulogi-tls", Addr: "r1.example.net:443", SNI: "vkvideo.ru"}
	link := RelayInvite("owl-eu-1", tr, "s3cr3t")
	inv, err := ParseInvite(link)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Kind != "relay" || inv.ID != "owl-eu-1" || inv.PSK != "s3cr3t" {
		t.Fatalf("roundtrip: %+v", inv)
	}
	if inv.Transport != tr {
		t.Fatalf("transport: %+v", inv.Transport)
	}
	// no psk
	inv2, err := ParseInvite(RelayInvite("x", Transport{Type: "qulogi-tcp", Addr: "h:443"}, ""))
	if err != nil || inv2.PSK != "" || inv2.Transport.Type != "qulogi-tcp" {
		t.Fatalf("psk-less invite: %+v err=%v", inv2, err)
	}
	// catalog
	cl := CatalogInvite("https://example.org/cat.json", "Community")
	ic, err := ParseInvite(cl)
	if err != nil || ic.Kind != "catalog" || ic.CatalogURL != "https://example.org/cat.json" {
		t.Fatalf("catalog invite: %+v err=%v", ic, err)
	}
	// malformed
	for _, bad := range []string{
		"", "https://example.org", "qulogi://unknown/?x=1",
		"qulogi://relay/x?type=qulogi-tls", "qulogi://catalog/?url=ftp://x",
	} {
		if _, err := ParseInvite(bad); err == nil {
			t.Errorf("ParseInvite(%q) should fail", bad)
		}
	}
}
