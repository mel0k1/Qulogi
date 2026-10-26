// Command qulogiturn is a minimal TURN server (RFC 5766 + RFC 6062 over
// TCP) for community relays and smoke tests. Production deployments can
// run coturn instead — the qulogi client speaks the standard protocol.
//
//	qulogiturn -listen :3478 [-user owl -realm qulogi -pass secret]
//
// Without -user the server is anonymous. Only TCP transports are served:
// the qulogi client uses RFC 6062 TCP peer connections (Allocate →
// Connect → ConnectionBind) to carry the tunnel stream.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/mel0k1/qulogi/internal/turnrelay"
)

func main() {
	var (
		listen = flag.String("listen", ":3478", "listen address")
		user   = flag.String("user", "", "username (empty = anonymous)")
		realm  = flag.String("realm", "qulogi", "realm for long-term credentials")
		pass   = flag.String("pass", "", "password (used with -user)")
	)
	flag.Parse()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "qulogiturn:", err)
		os.Exit(1)
	}
	srv := &turnrelay.Server{
		Listener: ln,
		User:     *user,
		Realm:    *realm,
		Pass:     *pass,
		Log: func(msg string) {
			fmt.Println(msg)
		},
	}
	go srv.Serve()
	mode := "anonymous"
	if *user != "" {
		mode = "user " + *user + " (realm " + *realm + ")"
	}
	fmt.Printf("qulogiturn on %s (%s)\n", ln.Addr(), mode)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	srv.Close()
}
