package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mel0k1/qulogi/internal/engine"
)

func main() {
	var (
		mode    = flag.String("mode", "dpi", "dpi, tunnel or vpn-egress helper (tunnel|dpi)")
		listen  = flag.String("listen", "127.0.0.1:1080", "local socks5 listen address")
		server  = flag.String("server", "", "tunnel server host:port")
		psk     = flag.String("psk", "", "pre-shared key")
		split   = flag.Int("split", 0, "clienthello split position, 0 = after sni, -1 = off")
		multi   = flag.Bool("multi", false, "extra split inside the ClientHello")
		camo    = flag.Bool("camo", false, "disguise the tunnel as TLS traffic to the whitelisted SNI")
		sni     = flag.String("sni", "vkvideo.ru", "SNI claimed by the camouflage ClientHello")
		fakeCH  = flag.Bool("fake-ch", false, "send the camouflage ClientHello as a separate flight")
		verbose = flag.Bool("v", false, "print engine events")
	)
	flag.Parse()

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
		Mode:   engine.Mode(*mode),
		Listen: *listen,
		Server: *server,
		PSK:    *psk,
		Split:  *split,
		Multi:  *multi,
		Camo:   *camo,
		SNI:    *sni,
		FakeCH: *fakeCH,
		Log:    logf,
	})
	if err := e.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "qulogi:", err)
		os.Exit(1)
	}
	st := e.Status()
	fmt.Printf("qulogi on %s (mode %s, camo=%v)\n", st.Listen, st.Mode, *camo)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	e.Stop()
}
