// qulogid is the Qulogi relay server. It accepts encrypted tunnel sessions
// on a TCP listener (optionally camouflaged as TLS) and, with -dav, also
// serves the storage-webdav transport: tunnel frames arriving as files in
// a whitelisted cloud mailbox (Yandex Disk, Nextcloud, ...).
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mel0k1/qulogi/internal/tunnel"
	"github.com/mel0k1/qulogi/internal/webdav"
)

func main() {
	var (
		listen     = flag.String("listen", ":443", "tunnel listen address (empty disables TCP)")
		psk        = flag.String("psk", "", "pre-shared key")
		dav        = flag.String("dav", "", "WebDAV endpoint for the storage transport, e.g. https://webdav.yandex.ru")
		davUser    = flag.String("dav-user", "", "WebDAV user")
		davPass    = flag.String("dav-pass", "", "WebDAV password")
		davMailbox = flag.String("dav-mailbox", "qulogi", "WebDAV mailbox directory to watch")
		verbose    = flag.Bool("v", false, "print tunnel events")
	)
	flag.Parse()

	if *psk == "" {
		fmt.Fprintln(os.Stderr, "qulogid: -psk is required")
		os.Exit(1)
	}
	if *listen == "" && *dav == "" {
		fmt.Fprintln(os.Stderr, "qulogid: nothing to serve: set -listen or -dav")
		os.Exit(1)
	}

	logf := func(string) {}
	if *verbose {
		logf = func(msg string) {
			fmt.Println(time.Now().Format("15:04:05"), msg)
		}
	}

	if *listen != "" {
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			fmt.Fprintln(os.Stderr, "qulogid:", err)
			os.Exit(1)
		}
		srv := &tunnel.Server{Listener: ln, PSK: []byte(*psk), Log: logf}
		fmt.Printf("qulogid on %s\n", ln.Addr())
		go srv.Serve()
	}

	if *dav != "" {
		cl, err := webdav.New(*dav, *davUser, *davPass)
		if err != nil {
			fmt.Fprintln(os.Stderr, "qulogid:", err)
			os.Exit(1)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			if err := webdav.ServeRelay(ctx, webdav.RelayConfig{
				Client:  cl,
				Mailbox: *davMailbox,
				PSK:     []byte(*psk),
				Log:     logf,
			}); err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "qulogid: dav relay:", err)
				os.Exit(1)
			}
		}()
		fmt.Printf("qulogid dav mailbox %s on %s\n", *davMailbox, *dav)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
