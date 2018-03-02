package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
)

type Server struct {
	ListenAddress string
	Certificate   []byte
	Key           []byte
	BindAddress   string
	BindPort      uint16
}

func (s *Server) Run() error {
	// Check the parameters are correctly polulated
	if len(s.Certificate) == 0 {
		return fmt.Errorf("server requires a TLS certificate")
	}
	if len(s.Key) == 0 {
		return fmt.Errorf("server requires a TLS key")
	}

	// Load up the TLS configuration
	cert, err := tls.X509KeyPair(s.Certificate, s.Key)
	if err != nil {
		return err
	}

	// Specify a minimum TLS connection of 1.2
	config := &tls.Config{
		Certificates: []tls.Certificate{
			cert,
		},
		MinVersion: tls.VersionTLS12,
	}

	// Create a TLS listener
	address := fmt.Sprintf("%s:%d", s.BindAddress, s.BindPort)
	listener, err := tls.Listen("tcp", address, config)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr: address,
	}

	// Start a routine to listen for termination signals which will shutdown
	// the HTTPS server cleanly.  Responds to SIGINT and SIGKILL
	shutdown := make(chan struct{})
	go func() {
		signals := make(chan os.Signal)
		signal.Notify(signals, os.Interrupt, os.Kill)
		<-signals

		if err := server.Shutdown(context.Background()); err != nil {
			fmt.Printf("HTTP server shutdown: %v", err)
		}
		close(shutdown)
	}()

	// Start the server
	if err := server.Serve(listener); err != http.ErrServerClosed {
		fmt.Printf("HTTP server serve: %v", err)
	}
	<-shutdown

	return nil
}
