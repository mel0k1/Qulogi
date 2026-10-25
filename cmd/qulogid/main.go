package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mel0k1/qulogi/internal/tunnel"
)

func main() {
	var (
		listen  = flag.String("listen", ":443", "tunnel listen address")
		psk     = flag.String("psk", "", "pre-shared key")
		verbose = flag.Bool("v", false, "print tunnel events")
	)
	flag.Parse()

	if *psk == "" {
		fmt.Fprintln(os.Stderr, "qulogid: -psk is required")
		os.Exit(1)
	}

	logf := func(string) {}
	if *verbose {
		logf = func(msg string) {
			fmt.Println(time.Now().Format("15:04:05"), msg)
		}
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "qulogid:", err)
		os.Exit(1)
	}
	srv := &tunnel.Server{Listener: ln, PSK: []byte(*psk), Log: logf}
	fmt.Printf("qulogid on %s\n", ln.Addr())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		ln.Close()
	}()
	srv.Serve()
}
