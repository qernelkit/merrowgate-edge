package server

import (
	"crypto/tls"
	"fmt"
)

// listenerConfig is the TLS setup of the control API listener on loopback. Its
// client is nginx, which also speaks only TLS 1.3 to it.
func listenerConfig(certFile, keyFile string) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("server: listener key pair: %w", err)
	}
	return &tls.Config{
		Certificates:     []tls.Certificate{pair},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	}, nil
}
