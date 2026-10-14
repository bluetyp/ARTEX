package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type oidcMemoryRecord struct {
	data    []byte
	expires time.Time
}
type oidcMemoryStore struct {
	sync.Mutex
	rows   map[string]oidcMemoryRecord
	broken bool
}

func (m *oidcMemoryStore) put(_ context.Context, k, h string, b []byte, e time.Time) error {
	m.Lock()
	defer m.Unlock()
	if m.broken {
		return errors.New("offline")
	}
	m.rows[k+h] = oidcMemoryRecord{b, e}
	return nil
}
func (m *oidcMemoryStore) get(_ context.Context, k, h string, consume bool) ([]byte, time.Time, error) {
	m.Lock()
	defer m.Unlock()
	if m.broken {
		return nil, time.Time{}, errors.New("offline")
	}
	v, ok := m.rows[k+h]
	if !ok || time.Now().After(v.expires) {
		return nil, time.Time{}, sql.ErrNoRows
	}
	if consume {
		delete(m.rows, k+h)
	}
	return v.data, v.expires, nil
}
func (m *oidcMemoryStore) remove(_ context.Context, k, h string) error {
	m.Lock()
	defer m.Unlock()
	if m.broken {
		return errors.New("offline")
	}
	delete(m.rows, k+h)
	return nil
}

type oidcFixture struct {
	a                                   *oidcAuth
	store                               *oidcMemoryStore
	server                              *httptest.Server
	nonce, role, app, subject, audience string
	permissionStatus, refreshes         int
	badSignature                        bool
	lastVerifier                        string
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	f := &oidcFixture{role: "artex:admin", app: "artex", subject: "u_test", audience: "artex-web", permissionStatus: 200}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/jwks", "userinfo_endpoint": f.server.URL + "/userinfo", "id_token_signing_alg_values_supported": []string{"ES256"}})
		case "/jwks":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "test", "use": "sig", "x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), "y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}}})
		case "/token":
			r.ParseForm()
			f.lastVerifier = r.Form.Get("code_verifier")
			if r.Form.Get("grant_type") == "refresh_token" {
				f.refreshes++
			}
			signingKey := key
			if f.badSignature {
				signingKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			}
			claims := jwt.MapClaims{"iss": f.server.URL, "sub": f.subject, "aud": f.audience, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "nonce": f.nonce, "roles": []string{"artex:admin"}}
			token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
			token.Header["kid"] = "test"
			raw, _ := token.SignedString(signingKey)
			json.NewEncoder(w).Encode(map[string]any{"access_token": "access-new", "token_type": "Bearer", "expires_in": 300, "refresh_token": "refresh-new", "id_token": raw})
		case "/userinfo":
			json.NewEncoder(w).Encode(map[string]any{"sub": f.subject, "nickname": "Operator", "roles": []string{"artex:admin"}})
		case "/perm/me":
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(401)
				return
			}
			w.WriteHeader(f.permissionStatus)
			json.NewEncoder(w).Encode(map[string]any{"app_id": f.app, "roles": []string{f.role}})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.server.Close)
	client := f.server.Client()
	client.Timeout = 2 * time.Second
	provider, err := oidc.NewProvider(oidc.ClientContext(context.Background(), client), f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := newOIDCCipher([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	f.store = &oidcMemoryStore{rows: map[string]oidcMemoryRecord{}}
	f.a = &oidcAuth{publicURL: "https://artex.example", appID: "artex", role: "artex:admin", permURL: f.server.URL + "/perm/me", provider: provider, client: client, store: f.store, aead: aead, oauth: oauth2.Config{ClientID: "artex-web", ClientSecret: "test-secret", Endpoint: provider.Endpoint(), RedirectURL: "https://artex.example/auth/callback", Scopes: []string{"openid", "profile"}}}
	return f
}
func (f *oidcFixture) request(method, path string, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://artex.example"+path, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	f.a.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })).ServeHTTP(w, r)
	return w
}
func (f *oidcFixture) flow(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	w := f.request("GET", "/auth/login", nil, "")
	if w.Code != 302 {
		t.Fatal(w.Code)
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	q := u.Query()
	f.nonce = q.Get("nonce")
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("redirect_uri") != "https://artex.example/auth/callback" {
		t.Fatal("bad PKCE redirect")
	}
	return q.Get("state"), w.Result().Cookies()[0]
}
func (f *oidcFixture) session(t *testing.T) *http.Cookie {
	t.Helper()
	s, c := f.flow(t)
	w := f.request("GET", "/auth/callback?code=valid&state="+s, c, "")
	if w.Code != 302 {
		t.Fatalf("callback %d: %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == oidcCookie {
			return c
		}
	}
	t.Fatal("missing session")
	return nil
}
func TestOIDCLoginSessionAndLogout(t *testing.T) {
	f := newOIDCFixture(t)
	cookie := f.session(t)
	if !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("insecure cookie")
	}
	if f.lastVerifier == "" {
		t.Fatal("missing code verifier")
	}
	for _, p := range []string{"/", "/auth/me", "/api/tasks", "/_next/static/test.js"} {
		if w := f.request("GET", p, cookie, ""); w.Code != 200 {
			t.Fatalf("%s %d", p, w.Code)
		}
	}
	for _, rec := range f.store.rows {
		if strings.Contains(string(rec.data), "access-new") || strings.Contains(string(rec.data), "u_test") {
			t.Fatal("plaintext secret in store")
		}
	}
	if w := f.request("POST", "/auth/logout", cookie, f.a.publicURL); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := f.request("GET", "/api/tasks", cookie, ""); w.Code != 401 {
		t.Fatal("logged-out session accepted", w.Code)
	}
}
func TestOIDCDenyBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*oidcFixture)
		code      int
	}{
		{"role_missing", func(f *oidcFixture) { f.role = "visitor" }, 403},
		{"wrong_app", func(f *oidcFixture) { f.app = "other" }, 403},
		{"permission_offline", func(f *oidcFixture) { f.permissionStatus = 503 }, 503},
		{"access_token_invalid", func(f *oidcFixture) { f.permissionStatus = 401 }, 401},
		{"bad_nonce", func(f *oidcFixture) { f.nonce = "wrong" }, 401},
		{"bad_audience", func(f *oidcFixture) { f.audience = "other" }, 401},
		{"bad_signature", func(f *oidcFixture) { f.badSignature = true }, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOIDCFixture(t)
			s, c := f.flow(t)
			tc.configure(f)
			w := f.request("GET", "/auth/callback?code=valid&state="+s, c, "")
			if w.Code != tc.code {
				t.Fatalf("got %d want %d", w.Code, tc.code)
			}
		})
	}
}
func TestOIDCStateBindingAndReplay(t *testing.T) {
	for _, mode := range []string{"missing_cookie", "wrong_cookie", "wrong_state", "replay"} {
		t.Run(mode, func(t *testing.T) {
			f := newOIDCFixture(t)
			s, c := f.flow(t)
			switch mode {
			case "missing_cookie":
				c = nil
			case "wrong_cookie":
				c.Value = oidcRandom()
			case "wrong_state":
				s = oidcRandom()
			case "replay":
				if f.request("GET", "/auth/callback?code=valid&state="+s, c, "").Code != 302 {
					t.Fatal("first login")
				}
			}
			if w := f.request("GET", "/auth/callback?code=valid&state="+s, c, ""); w.Code != 400 {
				t.Fatal(w.Code)
			}
		})
	}
}
func TestOIDCPrivateSurfaceAndCSRF(t *testing.T) {
	f := newOIDCFixture(t)
	cookie := f.session(t)
	for _, tc := range []struct {
		method, path, origin string
		cookie               *http.Cookie
		code                 int
	}{
		{"GET", "/", "", nil, 302}, {"GET", "/_next/static/a.js", "", nil, 302}, {"GET", "/api/tasks", "", nil, 401}, {"GET", "/auth/me", "", nil, 401},
		{"POST", "/api/auth/login", f.a.publicURL, nil, 403}, {"POST", "/api/auth/init", f.a.publicURL, nil, 403}, {"POST", "/api/auth/change-password", f.a.publicURL, cookie, 403},
		{"GET", "/setup", "", nil, 404}, {"GET", "/login", "", nil, 302}, {"GET", "/auth/logout", "", cookie, 405},
		{"POST", "/api/tasks", "", cookie, 403}, {"POST", "/api/tasks", "https://evil.example", cookie, 403}, {"POST", "/api/tasks", f.a.publicURL, cookie, 200},
	} {
		if w := f.request(tc.method, tc.path, tc.cookie, tc.origin); w.Code != tc.code {
			t.Errorf("%s %s: %d want %d", tc.method, tc.path, w.Code, tc.code)
		}
	}
	legacy, _ := signJWT([]byte(strings.Repeat("k", 32)))
	r := httptest.NewRequest("GET", "http://127.0.0.1/api/tasks?token="+legacy, nil)
	r.Header.Set("Authorization", "Bearer "+legacy)
	r.Header.Set("X-SSO-User", "admin")
	r.Header.Set("X-Auth-Request-Role", "artex:admin")
	r.AddCookie(&http.Cookie{Name: "artex_token", Value: legacy})
	w := httptest.NewRecorder()
	f.a.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })).ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("legacy/header bypass", w.Code)
	}
}
func TestOIDCRefreshExpiryAndStoreFailure(t *testing.T) {
	f := newOIDCFixture(t)
	cookie := f.session(t)
	var session oidcSession
	exp, err := f.a.load(context.Background(), "session", cookie.Value, false, &session)
	if err != nil {
		t.Fatal(err)
	}
	session.Token.Expiry = time.Now().Add(-time.Minute)
	session.Token.AccessToken = "access-old"
	f.a.save(context.Background(), "session", cookie.Value, session, exp)
	if w := f.request("GET", "/api/tasks", cookie, ""); w.Code != 200 || f.refreshes != 1 {
		t.Fatalf("refresh %d count%d", w.Code, f.refreshes)
	}
	f.role = "visitor"
	if w := f.request("GET", "/api/tasks", cookie, ""); w.Code != 403 {
		t.Fatal("permission not rechecked")
	}
	f.role = "artex:admin"
	f.store.broken = true
	if w := f.request("GET", "/api/tasks", cookie, ""); w.Code != 503 {
		t.Fatal("store failed open")
	}
	f.store.broken = false
	f.a.save(context.Background(), "session", cookie.Value, session, time.Now().Add(-time.Second))
	if w := f.request("GET", "/api/tasks", cookie, ""); w.Code != 401 {
		t.Fatal("expired session")
	}
}
func TestOIDCConfigurationFailsClosed(t *testing.T) {
	t.Setenv("ARTEX_AUTH_MODE", "typo")
	if _, err := newOIDCAuth(context.Background(), nil, nil); err == nil {
		t.Fatal("invalid mode")
	}
	t.Setenv("ARTEX_AUTH_MODE", "oidc")
	t.Setenv("ARTEX_PUBLIC_URL", "http://artex.example")
	if _, err := newOIDCAuth(context.Background(), nil, nil); err == nil {
		t.Fatal("insecure origin")
	}
}
