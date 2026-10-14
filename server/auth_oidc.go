package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const oidcCookie = "__Host-artex_sso"
const oidcFlowCookie = "__Host-artex_oidc_flow"
const oidcTTL = 8 * time.Hour

type oidcIdentity struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Avatar   string `json:"avatar"`
	Role     string `json:"role"`
}
type oidcSession struct {
	Token *oauth2.Token `json:"token"`
	User  oidcIdentity  `json:"user"`
}
type oidcFlow struct {
	Binding  string `json:"binding"`
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
}

// The database stores only hashed opaque handles and AES-GCM encrypted values.
type oidcStore interface {
	put(context.Context, string, string, []byte, time.Time) error
	get(context.Context, string, string, bool) ([]byte, time.Time, error)
	remove(context.Context, string, string) error
}
type oidcPGStore struct{ db *sql.DB }

func (p oidcPGStore) put(ctx context.Context, kind, key string, value []byte, expires time.Time) error {
	_, err := p.db.ExecContext(ctx, `INSERT INTO auth_oidc_sessions(kind,handle,payload,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(kind,handle) DO UPDATE SET payload=EXCLUDED.payload,expires_at=EXCLUDED.expires_at`, kind, key, value, expires)
	return err
}
func (p oidcPGStore) get(ctx context.Context, kind, key string, consume bool) ([]byte, time.Time, error) {
	query := `SELECT payload,expires_at FROM auth_oidc_sessions WHERE kind=$1 AND handle=$2 AND expires_at>NOW()`
	if consume {
		query = `DELETE FROM auth_oidc_sessions WHERE kind=$1 AND handle=$2 AND expires_at>NOW() RETURNING payload,expires_at`
	}
	var value []byte
	var expires time.Time
	err := p.db.QueryRowContext(ctx, query, kind, key).Scan(&value, &expires)
	return value, expires, err
}
func (p oidcPGStore) remove(ctx context.Context, kind, key string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM auth_oidc_sessions WHERE kind=$1 AND handle=$2`, kind, key)
	return err
}

type oidcAuth struct {
	publicURL, appID, role, permURL string
	provider                        *oidc.Provider
	oauth                           oauth2.Config
	client                          *http.Client
	store                           oidcStore
	aead                            cipher.AEAD
	// Serialize refresh+logout so rotated refresh tokens are never replayed by parallel requests.
	mu sync.Mutex
}
type oidcContextKey struct{}

func newOIDCAuth(ctx context.Context, db *sql.DB, key []byte) (*oidcAuth, error) {
	mode := os.Getenv("ARTEX_AUTH_MODE")
	if mode == "" || mode == "local" {
		return nil, nil
	}
	if mode != "oidc" {
		return nil, errors.New("invalid ARTEX_AUTH_MODE")
	}
	public := strings.TrimRight(os.Getenv("ARTEX_PUBLIC_URL"), "/")
	issuer := strings.TrimRight(os.Getenv("ARTEX_OIDC_ISSUER"), "/")
	for _, raw := range []string{public, issuer} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
			return nil, errors.New("OIDC requires canonical HTTPS origins")
		}
	}
	secret, err := os.ReadFile(os.Getenv("ARTEX_OIDC_CLIENT_SECRET_FILE"))
	if err != nil {
		return nil, errors.New("OIDC client secret unavailable")
	}
	clientID, appID, role := os.Getenv("ARTEX_OIDC_CLIENT_ID"), os.Getenv("ARTEX_OIDC_APP_ID"), os.Getenv("ARTEX_OIDC_ROLE")
	if clientID == "" || appID == "" || role == "" || len(strings.TrimSpace(string(secret))) < 32 {
		return nil, errors.New("incomplete OIDC configuration")
	}
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), issuer)
	if err != nil {
		return nil, errors.New("OIDC discovery unavailable")
	}
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS auth_oidc_sessions(kind TEXT NOT NULL,handle TEXT NOT NULL,payload BYTEA NOT NULL,expires_at TIMESTAMPTZ NOT NULL,PRIMARY KEY(kind,handle))`)
	if err != nil {
		return nil, errors.New("OIDC session store unavailable")
	}
	if _, err = db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS auth_oidc_sessions_expiry ON auth_oidc_sessions(expires_at)`); err != nil {
		return nil, errors.New("OIDC session index unavailable")
	}
	if _, err = db.ExecContext(ctx, `DELETE FROM auth_oidc_sessions WHERE expires_at<NOW()`); err != nil {
		return nil, err
	}
	a, err := newOIDCCipher(key)
	if err != nil {
		return nil, err
	}
	return &oidcAuth{publicURL: public, appID: appID, role: role, permURL: issuer + "/perm/me", provider: provider, client: client, store: oidcPGStore{db}, aead: a,
		oauth: oauth2.Config{ClientID: clientID, ClientSecret: strings.TrimSpace(string(secret)), Endpoint: provider.Endpoint(), RedirectURL: public + "/auth/callback", Scopes: []string{oidc.ScopeOpenID, "profile"}}}, nil
}
func newOIDCCipher(key []byte) (cipher.AEAD, error) {
	sum := sha256.Sum256(append([]byte("ARTEX OIDC session encryption v1:"), key...))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func oidcRandom() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("system entropy unavailable")
	}
	return hex.EncodeToString(b[:])
}
func oidcHash(v string) string { b := sha256.Sum256([]byte(v)); return hex.EncodeToString(b[:]) }
func (a *oidcAuth) save(ctx context.Context, kind, handle string, value any, expires time.Time) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	nonce := make([]byte, a.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	encrypted := a.aead.Seal(nonce, nonce, raw, []byte(kind+":"+oidcHash(handle)))
	return a.store.put(ctx, kind, oidcHash(handle), encrypted, expires)
}
func (a *oidcAuth) load(ctx context.Context, kind, handle string, consume bool, value any) (time.Time, error) {
	raw, expires, err := a.store.get(ctx, kind, oidcHash(handle), consume)
	if err != nil {
		return expires, err
	}
	n := a.aead.NonceSize()
	if len(raw) < n {
		return expires, errors.New("invalid session")
	}
	raw, err = a.aead.Open(nil, raw[:n], raw[n:], []byte(kind+":"+oidcHash(handle)))
	if err != nil {
		return expires, err
	}
	return expires, json.Unmarshal(raw, value)
}
func oidcSetCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	age := int(ttl.Seconds())
	if ttl < 0 {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func oidcCookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil || len(c.Value) != 64 {
		return ""
	}
	return c.Value
}
func (a *oidcAuth) permissions(ctx context.Context, token string) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.permURL, nil)
	if err != nil {
		return 503
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := a.client.Do(req)
	if err != nil {
		return 503
	}
	defer res.Body.Close()
	if res.StatusCode == 401 || res.StatusCode == 403 {
		return res.StatusCode
	}
	if res.StatusCode != 200 {
		return 503
	}
	var data struct {
		AppID string   `json:"app_id"`
		Roles []string `json:"roles"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&data) != nil || data.Roles == nil {
		return 503
	}
	if data.AppID != a.appID {
		return 403
	}
	for _, r := range data.Roles {
		if r == a.role {
			return 200
		}
	}
	return 403
}
func (a *oidcAuth) login(w http.ResponseWriter, r *http.Request) {
	state, binding, nonce := oidcRandom(), oidcRandom(), oidcRandom()
	verifier := oauth2.GenerateVerifier()
	if err := a.save(r.Context(), "flow", state, oidcFlow{binding, verifier, nonce}, time.Now().Add(10*time.Minute)); err != nil {
		writeErr(w, 503, "登录服务暂时不可用")
		return
	}
	oidcSetCookie(w, oidcFlowCookie, binding, 10*time.Minute)
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)), 302)
}
func (a *oidcAuth) callback(w http.ResponseWriter, r *http.Request) {
	state, binding := r.URL.Query().Get("state"), oidcCookieValue(r, oidcFlowCookie)
	oidcSetCookie(w, oidcFlowCookie, "", -time.Second)
	if len(state) != 64 || binding == "" || r.URL.Query().Get("code") == "" {
		writeErr(w, 400, "登录校验失败，请重新登录")
		return
	}
	var flow oidcFlow
	if _, err := a.load(r.Context(), "flow", state, true, &flow); err != nil || subtle.ConstantTimeCompare([]byte(binding), []byte(flow.Binding)) != 1 {
		writeErr(w, 400, "登录校验失败，请重新登录")
		return
	}
	ctx := oidc.ClientContext(r.Context(), a.client)
	token, err := a.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		writeErr(w, 502, "SSO 换取令牌失败")
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		writeErr(w, 502, "SSO 未返回身份令牌")
		return
	}
	id, err := a.provider.Verifier(&oidc.Config{ClientID: a.oauth.ClientID}).Verify(ctx, raw)
	if err != nil || id.Subject == "" || id.Nonce != flow.Nonce {
		writeErr(w, 401, "SSO 身份校验失败")
		return
	}
	if id.AccessTokenHash != "" && id.VerifyAccessToken(token.AccessToken) != nil {
		writeErr(w, 401, "SSO 令牌绑定校验失败")
		return
	}
	if code := a.permissions(ctx, token.AccessToken); code != 200 {
		writeErr(w, code, "此账号未获授权或权限服务暂不可用")
		return
	}
	// UserInfo supplies display identity only, never roles/permissions.
	name := id.Subject
	info, err := a.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil || info.Subject != id.Subject {
		writeErr(w, 502, "SSO 用户信息校验失败")
		return
	}
	var profile struct {
		Nickname string `json:"nickname"`
	}
	if info.Claims(&profile) == nil && profile.Nickname != "" {
		name = profile.Nickname
	}
	session := oidcSession{token, oidcIdentity{ID: id.Subject, Name: name, Username: name, Role: a.role}}
	handle := oidcRandom()
	if err := a.save(ctx, "session", handle, session, time.Now().Add(oidcTTL)); err != nil {
		writeErr(w, 503, "无法保存登录会话")
		return
	}
	log.Printf("[auth-audit] oidc_login user=%q app=%q role=%q", id.Subject, a.appID, a.role)
	oidcSetCookie(w, oidcCookie, handle, oidcTTL)
	http.Redirect(w, r, "/function/tasks", 302)
}
func (a *oidcAuth) authenticate(r *http.Request) (oidcIdentity, int) {
	handle := oidcCookieValue(r, oidcCookie)
	if handle == "" {
		return oidcIdentity{}, 401
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var session oidcSession
	expires, err := a.load(r.Context(), "session", handle, false, &session)
	if errors.Is(err, sql.ErrNoRows) {
		return oidcIdentity{}, 401
	}
	if err != nil {
		return oidcIdentity{}, 503
	}
	if session.Token == nil || session.User.ID == "" || time.Now().After(expires) {
		return oidcIdentity{}, 401
	}
	token, err := a.oauth.TokenSource(oidc.ClientContext(r.Context(), a.client), session.Token).Token()
	if err != nil {
		var oe *oauth2.RetrieveError
		if errors.As(err, &oe) && oe.ErrorCode == "invalid_grant" {
			_ = a.store.remove(r.Context(), "session", oidcHash(handle))
			return oidcIdentity{}, 401
		}
		return oidcIdentity{}, 503
	}
	if token.AccessToken != session.Token.AccessToken {
		session.Token = token
		if err := a.save(r.Context(), "session", handle, session, expires); err != nil {
			return oidcIdentity{}, 503
		}
	}
	if code := a.permissions(r.Context(), token.AccessToken); code != 200 {
		return oidcIdentity{}, code
	}
	return session.User, 200
}
func (a *oidcAuth) logout(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if handle := oidcCookieValue(r, oidcCookie); handle != "" {
		if err := a.store.remove(r.Context(), "session", oidcHash(handle)); err != nil {
			writeErr(w, 503, "退出暂时失败，请重试")
			return
		}
	}
	log.Printf("[auth-audit] oidc_logout app=%q", a.appID)
	oidcSetCookie(w, oidcCookie, "", -time.Second)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *oidcAuth) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
		p := r.URL.Path
		if r.Method != "GET" && r.Method != "HEAD" {
			if r.Header.Get("Origin") != a.publicURL || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				writeErr(w, 403, "跨站请求已拒绝")
				return
			}
		}
		switch p {
		case "/api/health":
			if r.Method == "GET" {
				next.ServeHTTP(w, r)
				return
			}
		case "/api/auth/status":
			if r.Method == "GET" {
				writeJSON(w, 200, map[string]any{"initialized": true, "mode": "oidc"})
				return
			}
		case "/api/auth/init", "/api/auth/login", "/api/auth/change-password":
			writeErr(w, 403, "本地密码登录已停用，请使用统一登录")
			return
		case "/setup", "/setup/":
			http.NotFound(w, r)
			return
		case "/login", "/login/":
			if r.Method == "GET" {
				http.Redirect(w, r, "/auth/login", 302)
				return
			}
		case "/auth/login":
			if r.Method == "GET" {
				a.login(w, r)
				return
			}
		case "/auth/callback":
			if r.Method == "GET" {
				a.callback(w, r)
				return
			}
		case "/auth/logout":
			if r.Method == "POST" {
				a.logout(w, r)
				return
			}
			w.WriteHeader(405)
			return
		case "/auth/logged-out":
			if r.Method == "GET" {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprint(w, `<!doctype html><title>ARTEX</title><main><p>已退出 ARTEX。</p><a href="/auth/login">使用统一身份重新登录</a></main>`)
				return
			}
		}
		user, code := a.authenticate(r)
		if code != 200 {
			if code == 401 && !strings.HasPrefix(p, "/api/") && p != "/auth/me" && (r.Method == "GET" || r.Method == "HEAD") {
				http.Redirect(w, r, "/auth/login", 302)
				return
			}
			writeErr(w, code, "未登录、无访问权限或鉴权服务暂不可用")
			return
		}
		if p == "/auth/me" {
			if r.Method != "GET" {
				w.WriteHeader(405)
				return
			}
			writeJSON(w, 200, user)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), oidcContextKey{}, true)))
	})
}
