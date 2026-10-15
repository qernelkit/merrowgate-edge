// Package server runs the control API listener and holds the client for the
// Merrowgate cloud.
package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

// The loopback listener presents the self-signed pair the image build puts in
// pki_dir. nginx, its only client, does not check it.
const (
	ListenerCertFile = "fallback.crt"
	ListenerKeyFile  = "fallback.key"
)

// Server is the control API listener.
type Server struct {
	http *http.Server
}

// New prepares the listener on addr with the certificate pair in certFile/keyFile.
func New(addr, certFile, keyFile string, h http.Handler) (*Server, error) {
	tc, err := listenerConfig(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &Server{http: &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         tc,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}}, nil
}

// Run serves until ctx is done, then drains connections for up to ten seconds.
func (s *Server) Run(ctx context.Context) error {
	errc := make(chan error, 1)
	go func() {
		log.Printf("control API listening on %s", s.http.Addr)
		errc <- s.http.ListenAndServeTLS("", "")
	}()
	select {
	case err := <-errc:
		return fmt.Errorf("server: %w", err)
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.http.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server: shutdown: %w", err)
	}
	return nil
}
