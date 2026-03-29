// Minimal CONNECT-IP proxy using connect-ip-go for interop testing.
// Accepts one connection, assigns an address, advertises a route,
// echoes IP packets, then exits.
//
// Usage: go run proxy.go <listen-addr> <cert-file> <key-file>
// Example: go run proxy.go 127.0.0.1:4433 cert.pem key.pem
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <listen-addr> <cert-file> <key-file>\n", os.Args[0])
		os.Exit(1)
	}
	listenAddr := os.Args[1]
	certFile := os.Args[2]
	keyFile := os.Args[3]

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load TLS cert: %v", err)
	}

	udpConn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer udpConn.Close()

	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/vpn", udpConn.(*net.UDPConn).LocalAddr().(*net.UDPAddr).Port))

	ln, err := quic.ListenEarly(
		udpConn,
		http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		&quic.Config{EnableDatagrams: true},
	)
	if err != nil {
		log.Fatalf("failed to create QUIC listener: %v", err)
	}
	defer ln.Close()

	var once sync.Once
	proxy := &connectip.Proxy{}

	mux := http.NewServeMux()
	mux.HandleFunc("/vpn", func(w http.ResponseWriter, r *http.Request) {
		req, err := connectip.ParseRequest(r, template)
		if err != nil {
			var perr *connectip.RequestParseError
			if errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		conn, err := proxy.Proxy(w, req)
		if err != nil {
			log.Fatalf("proxy error: %v", err)
		}

		handleConn(conn)
		once.Do(func() {
			// Signal that we're done by closing the listener
			ln.Close()
		})
	})

	s := http3.Server{Handler: mux, EnableDatagrams: true}
	go s.ServeListener(ln)

	// Print the listening address so the Rust test can parse it
	fmt.Printf("LISTENING %s\n", udpConn.LocalAddr().String())
	os.Stdout.Sync()

	// Wait for one connection to complete, then exit
	time.Sleep(30 * time.Second)
}

func handleConn(conn *connectip.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Assign address 100.64.0.1/32 to the client
	if err := conn.AssignAddresses(ctx, []netip.Prefix{
		netip.MustParsePrefix("100.64.0.1/32"),
	}); err != nil {
		log.Fatalf("failed to assign addresses: %v", err)
	}

	// Advertise route 10.0.0.0/24
	if err := conn.AdvertiseRoute(ctx, []connectip.IPRoute{
		{
			StartIP:    netip.MustParseAddr("10.0.0.0"),
			EndIP:      netip.MustParseAddr("10.0.0.255"),
			IPProtocol: 0,
		},
	}); err != nil {
		log.Fatalf("failed to advertise route: %v", err)
	}

	// Echo 3 packets then exit
	for i := 0; i < 3; i++ {
		buf := make([]byte, 1500)
		n, err := conn.ReadPacket(buf)
		if err != nil {
			log.Printf("read error (may be expected): %v", err)
			return
		}
		log.Printf("received %d byte packet", n)
		if _, err := conn.WritePacket(buf[:n]); err != nil {
			log.Printf("write error: %v", err)
			return
		}
	}

	conn.Close()
}
