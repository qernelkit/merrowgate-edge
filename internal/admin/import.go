package admin

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"merrowgate.example/edge/internal/seal"
)

// A v1 appliance exports its accounts (Settings > Backup) as
//
//	"MGX1" | salt (16 bytes) | nonce | ciphertext
//
// with the key derived from the export passphrase the operator typed.
var v1Magic = []byte("MGX1")

const v1SaltLen = 16

type v1Export struct {
	Exported time.Time `json:"exported"`
	Users    []struct {
		Login    string `json:"login"`
		FullName string `json:"full_name"`
		Hash     string `json:"hash"`
		Role     string `json:"role"`
		Disabled bool   `json:"disabled"`
	} `json:"users"`
}

// ImportV1 reads a v1 account export. Disabled users are skipped; roles map onto
// v2 roles, and anything unknown becomes a read-only viewer.
func ImportV1(export []byte, passphrase string) ([]Account, error) {
	rest, ok := bytes.CutPrefix(export, v1Magic)
	if !ok || len(rest) <= v1SaltLen {
		return nil, errors.New("admin: not a v1 account export")
	}
	salt, box := rest[:v1SaltLen], rest[v1SaltLen:]
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, 600000, 32)
	if err != nil {
		return nil, fmt.Errorf("admin: v1 export: %w", err)
	}
	plain, err := seal.OpenWithKey(key, box)
	if err != nil {
		return nil, fmt.Errorf("admin: v1 export: wrong export password or damaged file: %w", err)
	}
	var doc v1Export
	if err := json.Unmarshal(plain, &doc); err != nil {
		return nil, fmt.Errorf("admin: v1 export: %w", err)
	}
	var out []Account
	for _, u := range doc.Users {
		if u.Disabled || u.Login == "" {
			continue
		}
		out = append(out, Account{
			Login:    strings.ToLower(u.Login),
			FullName: u.FullName,
			Hash:     u.Hash,
			Role:     v1Role(u.Role),
			Created:  doc.Exported,
			FromV1:   true,
		})
	}
	return out, nil
}

func v1Role(r string) Role {
	switch strings.ToLower(r) {
	case "administrator", "admin":
		return RoleSupervisor
	case "technician":
		return RoleEngineer
	default:
		return RoleViewer
	}
}
