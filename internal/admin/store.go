package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"merrowgate.example/edge/internal/seal"
)

// Role is what an account may do.
type Role string

const (
	RoleSupervisor Role = "supervisor" // manage accounts, pair devices, roll out firmware
	RoleEngineer   Role = "engineer"   // bastion access, device diagnostics
	RoleViewer     Role = "viewer"     // read-only
)

// Account is one local admin account.
type Account struct {
	Login     string    `json:"login"`
	FullName  string    `json:"full_name"`
	Hash      string    `json:"hash"`
	Role      Role      `json:"role"`
	Created   time.Time `json:"created"`
	LastLogin time.Time `json:"last_login,omitzero"`
	FromV1    bool      `json:"from_v1,omitempty"`
}

// ErrNoAccount is returned for an unknown login.
var ErrNoAccount = errors.New("admin: no such account")

// Store keeps accounts in one sealed file under state_dir.
type Store struct {
	mu       sync.Mutex
	path     string
	master   []byte
	accounts map[string]Account
}

// OpenStore loads the account file, or starts empty when there is none yet.
func OpenStore(path string, master []byte) (*Store, error) {
	s := &Store{path: path, master: master, accounts: map[string]Account{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("admin: %w", err)
	}
	plain, err := seal.Open(master, strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("admin: %s: %w", path, err)
	}
	var list []Account
	if err := json.Unmarshal(plain, &list); err != nil {
		return nil, fmt.Errorf("admin: %s: %w", path, err)
	}
	for _, a := range list {
		s.accounts[a.Login] = a
	}
	return s, nil
}

// Get returns the account for login.
func (s *Store) Get(login string) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[strings.ToLower(login)]
	if !ok {
		return Account{}, ErrNoAccount
	}
	return a, nil
}

// Put adds or replaces accounts and writes the file.
func (s *Store) Put(accounts ...Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range accounts {
		s.accounts[a.Login] = a
	}
	return s.save()
}

// Len is the number of accounts.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.accounts)
}

func (s *Store) save() error {
	list := make([]Account, 0, len(s.accounts))
	for _, a := range s.accounts {
		list = append(list, a)
	}
	slices.SortFunc(list, func(a, b Account) int { return strings.Compare(a.Login, b.Login) })
	plain, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("admin: %w", err)
	}
	sealed, err := seal.Seal(s.master, plain)
	if err != nil {
		return err
	}
	tmp := s.path + ".new"
	if err := os.WriteFile(tmp, []byte(sealed+"\n"), 0o600); err != nil {
		return fmt.Errorf("admin: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("admin: %w", err)
	}
	return nil
}
