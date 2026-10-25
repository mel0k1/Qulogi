package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mel0k1/qulogi/internal/engine"
	"github.com/mel0k1/qulogi/mobile"
)

func main() {
	var (
		mode         = flag.String("mode", "dpi", "dpi, tunnel or vpn-egress helper (tunnel|dpi)")
		listen       = flag.String("listen", "127.0.0.1:1080", "local socks5 listen address")
		server       = flag.String("server", "", "tunnel server host:port")
		psk          = flag.String("psk", "", "pre-shared key")
		split        = flag.Int("split", 0, "clienthello split position, 0 = after sni, -1 = off")
		multi        = flag.Bool("multi", false, "extra split inside the ClientHello")
		camo         = flag.Bool("camo", false, "disguise the tunnel as TLS traffic to the whitelisted SNI")
		sni          = flag.String("sni", "vkvideo.ru", "SNI claimed by the camouflage ClientHello")
		fakeCH       = flag.Bool("fake-ch", false, "send the camouflage ClientHello as a separate flight")
		smart        = flag.Bool("smart-split", false, "whitelisted destinations bypass the tunnel")
		direct       = flag.String("direct-domains", "", "extra direct rules, comma-separated")
		proxy        = flag.String("proxy-domains", "", "force-through-tunnel rules, comma-separated")
		dav          = flag.String("dav", "", "WebDAV endpoint (storage transport), e.g. https://webdav.yandex.ru")
		cdn          = flag.String("cdn", "", "CDN edge host:port (cdn-front transport)")
		cdnSNI       = flag.String("cdn-sni", "", "whitelisted SNI for the CDN edge")
		cdnHost      = flag.String("cdn-host", "", "relay hostname behind the CDN (Host header)")
		botlpURL     = flag.String("botlp", "", "platform long-poll API base (bot-longpoll transport)")
		botlpToken   = flag.String("botlp-token", "", "platform bot token")
		botlpRoom    = flag.String("botlp-room", "", "operator base room")
		davUser      = flag.String("dav-user", "", "WebDAV user")
		davPass      = flag.String("dav-pass", "", "WebDAV password")
		davMailbox   = flag.String("dav-mailbox", "qulogi", "WebDAV mailbox directory")
		discoverJSON = flag.String("discover", "", "fetch the relay catalog (params JSON) and print the report, then exit")
		verbose      = flag.Bool("v", false, "print engine events")
	)
	flag.Parse()

	if *discoverJSON != "" {
		fmt.Println(mobile.FetchDirectory(*discoverJSON))
		return
	}

	if *dav != "" && *mode == "dpi" {
		*mode = "tunnel"
	}
	if *cdn != "" && *mode == "dpi" {
		*mode = "tunnel"
	}
	if *botlpURL != "" && *mode == "dpi" {
		*mode = "tunnel"
	}
	if *server != "" && *mode == "dpi" {
		*mode = "tunnel"
	}

	logf := func(string) {}
	if *verbose {
		logf = func(msg string) {
			fmt.Println(time.Now().Format("15:04:05"), msg)
		}
	}

	e := engine.New(engine.Config{
		Mode:       engine.Mode(*mode),
		Listen:     *listen,
		Server:     *server,
		PSK:        *psk,
		Split:      *split,
		Multi:      *multi,
		Camo:       *camo,
		SNI:        *sni,
		FakeCH:     *fakeCH,
		SmartSplit: *smart,
		Direct:     splitList(*direct),
		Proxy:      splitList(*proxy),
		DAVURL:     *dav,
		CDNEdge:    *cdn,
		CDNSNI:     *cdnSNI,
		CDNHost:    *cdnHost,
		BotLPURL:   *botlpURL,
		BotLPToken: *botlpToken,
		BotLPRoom:  *botlpRoom,
		DAVUser:    *davUser,
		DAVPass:    *davPass,
		DAVMailbox: *davMailbox,
		Log:        logf,
	})
	if err := e.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "qulogi:", err)
		os.Exit(1)
	}
	st := e.Status()
	fmt.Printf("qulogi on %s (mode %s, camo=%v, smart-split=%v, dav=%v)\n", st.Listen, st.Mode, *camo, *smart, *dav != "")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	e.Stop()
}

func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
