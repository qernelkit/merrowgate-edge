package session

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"merrowgate.example/edge/internal/seal"
)

// Offer is what the gateway returns when an engineer pairs a new device. The device
// computes the same shared secret from GatewayKey and its own key, and opens
// Credentials with it to get its first device token.
type Offer struct {
	GatewayKey  []byte `json:"gateway_key"`
	Credentials string `json:"credentials"`
}

// Pair answers a pairing request from a device that showed its public key (raw,
// 32 bytes) on its display as a QR code. credentials is the device's first token.
func Pair(devicePub []byte, credentials string) (*Offer, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("session: gateway key: %w", err)
	}
	peer, err := ecdh.X25519().NewPublicKey(devicePub)
	if err != nil {
		return nil, fmt.Errorf("session: device key: %w", err)
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("session: shared secret: %w", err)
	}
	sealed, err := seal.Seal(shared, []byte(credentials))
	if err != nil {
		return nil, err
	}
	return &Offer{GatewayKey: priv.PublicKey().Bytes(), Credentials: sealed}, nil
}
