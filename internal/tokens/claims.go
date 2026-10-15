package tokens

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"

	"github.com/golang-jwt/jwt/v5"
)

// Scopes a device token can grant.
const (
	ScopeTelemetry = "telemetry:write"
	ScopeSession   = "session:open"
	ScopeAttest    = "attest"
	ScopeFirmware  = "firmware:read"
)

// DeviceClaims are the claims carried in a device token.
type DeviceClaims struct {
	Site   string   `json:"site"`
	Scopes []string `json:"scp"`
	jwt.RegisteredClaims
}

// Allows reports whether the token grants scope.
func (c *DeviceClaims) Allows(scope string) bool {
	return slices.Contains(c.Scopes, scope)
}

// DefaultScopes are granted to a newly paired device.
func DefaultScopes() []string {
	return []string{ScopeTelemetry, ScopeSession, ScopeAttest, ScopeFirmware}
}

// Cursor is a position in a paged device listing. Clients get it as an opaque
// string and send it back unchanged to fetch the next page.
type Cursor struct {
	After string `json:"a"`
	Limit int    `json:"n"`
}

// Encode returns the cursor in the form clients see.
func (c Cursor) Encode() string {
	raw, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// ParseCursor reads a cursor a client sent back. An empty string is the first page.
func ParseCursor(s string, defaultLimit int) (Cursor, error) {
	if s == "" {
		return Cursor{Limit: defaultLimit}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Cursor{}, errors.New("tokens: malformed cursor")
	}
	var c Cursor
	if err := json.Unmarshal(b, &c); err != nil || c.Limit < 1 || c.Limit > 500 {
		return Cursor{}, errors.New("tokens: malformed cursor")
	}
	return c, nil
}
