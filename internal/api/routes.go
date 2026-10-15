// Package api is the gateway's control API, served behind nginx under /api/, and
// the field-operations page under /ops/ (nginx adds basic auth in front of it).
//
// Device endpoints take a device token (Authorization: Bearer). Admin endpoints
// take the login cookie set by POST /api/v1/admin/login.
package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"merrowgate.example/edge/internal/admin"
	"merrowgate.example/edge/internal/attest"
	"merrowgate.example/edge/internal/audit"
	"merrowgate.example/edge/internal/config"
	"merrowgate.example/edge/internal/depots"
	"merrowgate.example/edge/internal/firmware"
	"merrowgate.example/edge/internal/mqtt"
	"merrowgate.example/edge/internal/session"
	"merrowgate.example/edge/internal/sshca"
	"merrowgate.example/edge/internal/tokens"
	"merrowgate.example/edge/internal/webhook"
)

// Deps are the services the API needs; main builds them from gateway.yaml.
type Deps struct {
	Config   *config.Config
	Issuer   *tokens.Issuer
	Hasher   *admin.Hasher
	Accounts *admin.Store
	Keyring  *session.Keyring
	Relay    *mqtt.Relay
	Firmware *firmware.Verifier
	SSHCA    *sshca.Authority
	Audit    *audit.Log
	Webhooks *webhook.Sender
}

// API holds the handlers' state.
type API struct {
	Deps
	site       depots.Site
	devices    *registry
	cache      *responseCache
	logins     sync.Map // cookie value -> login
	challenges sync.Map // device ID -> challenge
}

const loginCookie = "mg_login"

// New opens the device registry and returns the API.
func New(d Deps) (*API, error) {
	site, _ := depots.Lookup(d.Config.Depot.Site)
	reg, err := openRegistry(d.Config.StatePath("devices.json"))
	if err != nil {
		return nil, err
	}
	return &API{Deps: d, site: site, devices: reg, cache: newResponseCache(5 * time.Second)}, nil
}

// Handler returns the routed, rate-limited API.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /ops/", a.opsPage)
	mux.HandleFunc("GET /api/v1/depot", a.depotInfo)
	mux.HandleFunc("POST /api/v1/admin/login", a.login)
	mux.HandleFunc("GET /api/v1/devices", a.requireLogin(admin.RoleViewer, a.listDevices))
	mux.HandleFunc("POST /api/v1/devices/{id}/pair", a.requireLogin(admin.RoleSupervisor, a.pairDevice))
	mux.HandleFunc("POST /api/v1/firmware/{model}/{version}/check", a.requireLogin(admin.RoleSupervisor, a.checkFirmware))
	mux.HandleFunc("POST /api/v1/engineers/access", a.requireLogin(admin.RoleEngineer, a.engineerAccess))
	mux.HandleFunc("GET /api/v1/engineers/authority", a.engineerAuthority)
	mux.HandleFunc("GET /api/v1/session/key", a.requireDevice(tokens.ScopeSession, a.sessionKey))
	mux.HandleFunc("POST /api/v1/session", a.requireDevice(tokens.ScopeSession, a.openSession))
	mux.HandleFunc("POST /api/v1/telemetry", a.requireDevice(tokens.ScopeTelemetry, a.telemetry))
	mux.HandleFunc("GET /api/v1/attest/challenge", a.requireDevice(tokens.ScopeAttest, a.attestChallenge))
	mux.HandleFunc("POST /api/v1/attest", a.requireDevice(tokens.ScopeAttest, a.attestQuote))
	return rateLimit(logRequests(mux))
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// ---- authentication

type deviceHandler func(w http.ResponseWriter, r *http.Request, claims *tokens.DeviceClaims)

func (a *API) requireDevice(scope string, h deviceHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			httpError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		claims, err := a.Issuer.Check(raw)
		if err != nil {
			log.Printf("device token from %s: %v", clientAddr(r), err)
			httpError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if !claims.Allows(scope) {
			httpError(w, http.StatusForbidden, "token does not grant "+scope)
			return
		}
		h(w, r, claims)
	}
}

type loginHandler func(w http.ResponseWriter, r *http.Request, acct admin.Account)

var roleRank = map[admin.Role]int{admin.RoleViewer: 1, admin.RoleEngineer: 2, admin.RoleSupervisor: 3}

func (a *API) requireLogin(least admin.Role, h loginHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(loginCookie)
		if err != nil {
			httpError(w, http.StatusUnauthorized, "sign in first")
			return
		}
		v, ok := a.logins.Load(c.Value)
		if !ok {
			httpError(w, http.StatusUnauthorized, "sign in first")
			return
		}
		s := v.(loginState)
		if time.Now().After(s.expires) {
			a.logins.Delete(c.Value)
			httpError(w, http.StatusUnauthorized, "signed out after inactivity")
			return
		}
		acct, err := a.Accounts.Get(s.login)
		if err != nil || roleRank[acct.Role] < roleRank[least] {
			httpError(w, http.StatusForbidden, "your role cannot do this")
			return
		}
		h(w, r, acct)
	}
}

type loginState struct {
	login   string
	expires time.Time
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	acct, err := a.Accounts.Get(req.Login)
	if err != nil {
		httpError(w, http.StatusUnauthorized, "wrong login or password")
		return
	}
	rehash, err := a.Hasher.Verify(acct.Hash, req.Password)
	if err != nil {
		a.audit("login-failed", acct.Login, "")
		httpError(w, http.StatusUnauthorized, "wrong login or password")
		return
	}
	acct.LastLogin = time.Now()
	if rehash {
		if h, err := a.Hasher.Hash(req.Password); err == nil {
			acct.Hash, acct.FromV1 = h, false
		}
	}
	if err := a.Accounts.Put(acct); err != nil {
		log.Printf("login %s: %v", acct.Login, err)
	}
	id, err := randomID()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "try again")
		return
	}
	a.logins.Store(id, loginState{login: acct.Login, expires: time.Now().Add(a.Config.Admin.LoginTTL)})
	http.SetCookie(w, &http.Cookie{Name: loginCookie, Value: id, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	a.audit("login", acct.Login, "")
	writeJSON(w, http.StatusOK, map[string]string{"login": acct.Login, "role": string(acct.Role)})
}

// ---- depot and devices

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "ok\n")
}

func (a *API) depotInfo(w http.ResponseWriter, r *http.Request) {
	body, err := a.cache.get("depot", time.Now(), func() ([]byte, error) {
		return json.Marshal(map[string]any{
			"site":     a.site.Code,
			"city":     a.site.City,
			"docks":    a.site.Docks,
			"gateway":  a.Config.Depot.GatewayID,
			"devices":  a.deviceCount(),
			"accounts": a.Accounts.Len(),
			"time":     time.Now().In(a.site.Location()).Format(time.RFC3339),
		})
	})
	if err != nil {
		httpError(w, http.StatusInternalServerError, "render failed")
		return
	}
	writeCacheable(w, r, body)
}

var opsTemplate = template.Must(template.New("ops").Parse(`<!doctype html>
<title>{{.Gateway}} | field operations</title>
<h1>{{.Site}} {{.Gateway}}</h1>
<table>
<tr><th>Local time</th><td>{{.Now}}</td></tr>
<tr><th>Paired devices</th><td>{{.Devices}}</td></tr>
<tr><th>Admin accounts</th><td>{{.Accounts}}</td></tr>
<tr><th>Session key since</th><td>{{.KeySince}}</td></tr>
</table>
<p>Bastion access: <code>POST /api/v1/engineers/access</code> with your authorized_keys line.</p>
`))

// opsPage is the status page field engineers open from the depot VPN.
func (a *API) opsPage(w http.ResponseWriter, r *http.Request) {
	_, since := a.Keyring.Published()
	loc := a.site.Location()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	opsTemplate.Execute(w, map[string]any{
		"Site":     a.site.City,
		"Gateway":  a.Config.Depot.GatewayID,
		"Now":      time.Now().In(loc).Format("2006-01-02 15:04 MST"),
		"Devices":  a.deviceCount(),
		"Accounts": a.Accounts.Len(),
		"KeySince": since.In(loc).Format("2006-01-02 15:04 MST"),
	})
}

func (a *API) deviceCount() int {
	list, _ := a.devices.page("", 1<<20)
	return len(list)
}

func (a *API) listDevices(w http.ResponseWriter, r *http.Request, _ admin.Account) {
	cur, err := tokens.ParseCursor(r.URL.Query().Get("cursor"), 100)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	list, more := a.devices.page(cur.After, cur.Limit)
	resp := map[string]any{"devices": list}
	if more {
		resp["next"] = tokens.Cursor{After: list[len(list)-1].ID, Limit: cur.Limit}.Encode()
	}
	body, err := json.Marshal(resp)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "render failed")
		return
	}
	writeCacheable(w, r, body)
}

func (a *API) pairDevice(w http.ResponseWriter, r *http.Request, acct admin.Account) {
	id := r.PathValue("id")
	if !strings.HasPrefix(id, strings.ToLower(a.site.Code)+"-") {
		httpError(w, http.StatusBadRequest, "device IDs at this depot start with "+strings.ToLower(a.site.Code)+"-")
		return
	}
	var req struct {
		Model     string `json:"model"`
		Dock      int    `json:"dock"`
		DeviceKey []byte `json:"device_key"`
		AttestKey []byte `json:"attest_key"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tok, err := a.Issuer.Issue(id, a.site.Code, tokens.DefaultScopes(), time.Now())
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not issue a device token")
		return
	}
	offer, err := session.Pair(req.DeviceKey, tok)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	dev := Device{ID: id, Model: req.Model, Dock: req.Dock, Paired: time.Now(), AttestKey: req.AttestKey}
	if err := a.devices.put(dev); err != nil {
		httpError(w, http.StatusInternalServerError, "could not save the device")
		return
	}
	a.cache.drop("depot")
	a.audit("device-paired", acct.Login, id)
	a.notify(r.Context(), webhook.Event{Kind: "device.paired", Device: id, Detail: map[string]string{"model": req.Model, "by": acct.Login}})
	writeJSON(w, http.StatusOK, offer)
}

// ---- firmware

func (a *API) checkFirmware(w http.ResponseWriter, r *http.Request, acct admin.Account) {
	model, version := r.PathValue("model"), r.PathValue("version")
	if strings.ContainsAny(model+version, `/\`) || strings.Contains(model+version, "..") {
		httpError(w, http.StatusBadRequest, "bad model or version")
		return
	}
	dir := filepath.Join(a.Config.StatePath("firmware"), model, version)
	rel, err := a.Firmware.CheckBundle(dir)
	if err != nil {
		a.audit("firmware-rejected", acct.Login, model+"/"+version)
		httpError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	a.audit("firmware-accepted", acct.Login, model+"/"+version)
	writeJSON(w, http.StatusOK, rel)
}

// ---- engineers

func (a *API) engineerAccess(w http.ResponseWriter, r *http.Request, acct admin.Account) {
	var req struct {
		AuthorizedKey string `json:"authorized_key"`
		Reason        string `json:"reason"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		httpError(w, http.StatusBadRequest, "say why you need bastion access")
		return
	}
	line, err := a.SSHCA.Issue(acct.Login, []byte(req.AuthorizedKey), a.Config.Engineers.Principals)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.audit("bastion-access", acct.Login, req.Reason)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(line)
}

func (a *API) engineerAuthority(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(a.SSHCA.AuthorizedKey())
}

// ---- device sessions and telemetry

func (a *API) sessionKey(w http.ResponseWriter, r *http.Request, _ *tokens.DeviceClaims) {
	key, since := a.Keyring.Published()
	writeJSON(w, http.StatusOK, map[string]any{"key": key, "since": since})
}

func (a *API) openSession(w http.ResponseWriter, r *http.Request, claims *tokens.DeviceClaims) {
	var req struct {
		KeyHint    []byte `json:"key_hint"`
		Ciphertext []byte `json:"ciphertext"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if a.Config.Attestation.Required {
		if dev, err := a.devices.get(claims.Subject); err == nil && len(dev.AttestKey) > 0 && dev.Attested.IsZero() {
			httpError(w, http.StatusForbidden, "attest before opening a session")
			return
		}
	}
	key, err := a.Keyring.Accept(req.KeyHint, req.Ciphertext)
	if errors.Is(err, session.ErrUnknownKey) {
		httpError(w, http.StatusConflict, "fetch the current key and try again")
		return
	}
	if err != nil {
		httpError(w, http.StatusBadRequest, "could not open the session")
		return
	}
	if err := a.Relay.SetSessionKey(claims.Subject, key); err != nil {
		httpError(w, http.StatusInternalServerError, "could not open the session")
		return
	}
	a.devices.update(claims.Subject, func(d *Device) { d.LastSeen = time.Now() })
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) telemetry(w http.ResponseWriter, r *http.Request, claims *tokens.DeviceClaims) {
	body, err := io.ReadAll(io.LimitReader(r.Body, mqtt.MaxReading+1024))
	if err != nil {
		httpError(w, http.StatusBadRequest, "read failed")
		return
	}
	if err := a.Relay.Forward(claims.Subject, body); err != nil {
		if errors.Is(err, mqtt.ErrNoSession) {
			httpError(w, http.StatusPreconditionRequired, "open a session first")
			return
		}
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// ---- attestation

func (a *API) attestChallenge(w http.ResponseWriter, r *http.Request, claims *tokens.DeviceClaims) {
	c := make([]byte, 32)
	if _, err := rand.Read(c); err != nil {
		httpError(w, http.StatusInternalServerError, "try again")
		return
	}
	a.challenges.Store(claims.Subject, pendingChallenge{value: c, expires: time.Now().Add(a.Config.Attestation.ChallengeTTL)})
	writeJSON(w, http.StatusOK, map[string][]byte{"challenge": c})
}

type pendingChallenge struct {
	value   []byte
	expires time.Time
}

func (a *API) attestQuote(w http.ResponseWriter, r *http.Request, claims *tokens.DeviceClaims) {
	var q attest.Quote
	if !readJSON(w, r, &q) {
		return
	}
	v, ok := a.challenges.LoadAndDelete(claims.Subject)
	if !ok || time.Now().After(v.(pendingChallenge).expires) {
		httpError(w, http.StatusConflict, "request a new challenge")
		return
	}
	dev, err := a.devices.get(claims.Subject)
	if err != nil || len(dev.AttestKey) == 0 {
		httpError(w, http.StatusBadRequest, "this device has no attestation key on record")
		return
	}
	if err := attest.Verify(dev.AttestKey, q, v.(pendingChallenge).value); err != nil {
		a.audit("attestation-failed", claims.Subject, err.Error())
		a.notify(r.Context(), webhook.Event{Kind: "device.attestation_failed", Device: claims.Subject})
		httpError(w, http.StatusForbidden, "attestation failed")
		return
	}
	a.devices.update(claims.Subject, func(d *Device) { d.Attested = time.Now() })
	w.WriteHeader(http.StatusNoContent)
}

// ---- helpers

func (a *API) audit(action, actor, target string) {
	if err := a.Audit.Append(actor, action, target); err != nil {
		log.Printf("audit %s by %s: %v", action, actor, err)
	}
}

func (a *API) notify(ctx context.Context, ev webhook.Event) {
	ev.Site, ev.At = a.site.Code, time.Now().UTC()
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		a.Webhooks.Send(ctx, ev)
	}()
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		httpError(w, http.StatusBadRequest, fmt.Sprintf("bad request body: %v", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func randomID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
