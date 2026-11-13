package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "ssh_buttons_session"
	sessionDuration   = 24 * time.Hour
)

// LoginRateLimiter limits failed login attempts by client IP to prevent brute-forcing
type LoginRateLimiter struct {
	mu          sync.Mutex
	attempts    map[string][]time.Time
	maxAttempts int
	window      time.Duration
}

func NewLoginRateLimiter(maxAttempts int, window time.Duration) *LoginRateLimiter {
	return &LoginRateLimiter{
		attempts:    make(map[string][]time.Time),
		maxAttempts: maxAttempts,
		window:      window,
	}
}

// Allow returns true if the IP has not exceeded maxAttempts in window
func (l *LoginRateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)

	var recent []time.Time
	for _, t := range l.attempts[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	l.attempts[ip] = recent

	return len(recent) < l.maxAttempts
}

// RecordFailure notes a failed attempt
func (l *LoginRateLimiter) RecordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempts[ip] = append(l.attempts[ip], time.Now())
}

// RecordSuccess clears history on successful authentication
func (l *LoginRateLimiter) RecordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
}

type AuthService struct {
	configMgr *ConfigManager
	limiter   *LoginRateLimiter
}

func NewAuthService(cm *ConfigManager) *AuthService {
	return &AuthService{
		configMgr: cm,
		limiter:   NewLoginRateLimiter(5, 1*time.Minute),
	}
}

// AllowLogin checks rate limiting for client IP
func (a *AuthService) AllowLogin(ip string) bool {
	return a.limiter.Allow(ip)
}

// RecordLoginFailure tracks a failed login for client IP
func (a *AuthService) RecordLoginFailure(ip string) {
	a.limiter.RecordFailure(ip)
}

// RecordLoginSuccess clears failed login records on success
func (a *AuthService) RecordLoginSuccess(ip string) {
	a.limiter.RecordSuccess(ip)
}

// GetClientIP extracts remote IP considering reverse proxy headers
func GetClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// CheckCredentials validates username and password against configured users.
// Password can be plain text or bcrypt hash (starts with $2a$, $2b$, or $2y$).
func (a *AuthService) CheckCredentials(username, password string) bool {
	cfg := a.configMgr.Get()

	user, exists := cfg.UsersByUsername[username]
	if !exists {
		return false
	}

	storedPass := user.Password
	if strings.HasPrefix(storedPass, "$2a$") || strings.HasPrefix(storedPass, "$2b$") || strings.HasPrefix(storedPass, "$2y$") {
		err := bcrypt.CompareHashAndPassword([]byte(storedPass), []byte(password))
		return err == nil
	}

	return subtle.ConstantTimeCompare([]byte(password), []byte(storedPass)) == 1
}

// GetUserRole returns the role ("admin" or "operator") of the given user
func (a *AuthService) GetUserRole(username string) string {
	cfg := a.configMgr.Get()
	if user, exists := cfg.UsersByUsername[username]; exists {
		return user.Role
	}
	return ""
}

// GenerateSessionToken creates a signed token in format: base64(username:expiresAtUnix:signature)
func (a *AuthService) GenerateSessionToken(username string) string {
	cfg := a.configMgr.Get()
	expiresAt := time.Now().Add(sessionDuration).Unix()
	payload := fmt.Sprintf("%s:%d", username, expiresAt)

	mac := hmac.New(sha256.New, []byte(cfg.Server.SessionSecret))
	mac.Write([]byte(payload))
	signature := mac.Sum(nil)

	tokenStr := fmt.Sprintf("%s:%s", payload, base64.RawURLEncoding.EncodeToString(signature))
	return base64.RawURLEncoding.EncodeToString([]byte(tokenStr))
}

// ValidateSessionToken checks the signature and expiration of a session token
func (a *AuthService) ValidateSessionToken(token string) (string, bool) {
	if token == "" {
		return "", false
	}

	rawBytes, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", false
	}

	parts := strings.Split(string(rawBytes), ":")
	if len(parts) != 3 {
		return "", false
	}

	username := parts[0]
	expiresAtStr := parts[1]
	sigBase64 := parts[2]

	expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64)
	if err != nil || time.Now().Unix() > expiresAt {
		return "", false
	}

	cfg := a.configMgr.Get()
	// Check if user still exists in current configuration
	if _, exists := cfg.UsersByUsername[username]; !exists {
		return "", false
	}

	expectedMac := hmac.New(sha256.New, []byte(cfg.Server.SessionSecret))
	expectedMac.Write(fmt.Appendf(nil, "%s:%s", username, expiresAtStr))
	expectedSig := expectedMac.Sum(nil)

	actualSig, err := base64.RawURLEncoding.DecodeString(sigBase64)
	if err != nil {
		return "", false
	}

	if !hmac.Equal(expectedSig, actualSig) {
		return "", false
	}

	return username, true
}

// GenerateCSRFToken creates a stateless session-bound CSRF token for the authenticated user
func (a *AuthService) GenerateCSRFToken(username string) string {
	if username == "" {
		return ""
	}
	cfg := a.configMgr.Get()
	epoch := time.Now().Unix() / 86400
	payload := fmt.Sprintf("csrf:%s:%d", username, epoch)

	mac := hmac.New(sha256.New, []byte(cfg.Server.SessionSecret))
	mac.Write([]byte(payload))
	signature := mac.Sum(nil)

	token := fmt.Sprintf("%s:%s", payload, base64.RawURLEncoding.EncodeToString(signature))
	return base64.RawURLEncoding.EncodeToString([]byte(token))
}

// ValidateCSRFToken verifies that the CSRF token matches the authenticated user and server secret
func (a *AuthService) ValidateCSRFToken(username, token string) bool {
	if username == "" || token == "" {
		return false
	}
	rawBytes, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	parts := strings.Split(string(rawBytes), ":")
	if len(parts) != 4 || parts[0] != "csrf" {
		return false
	}
	tokenUser := parts[1]
	epochStr := parts[2]
	sigBase64 := parts[3]

	if tokenUser != username {
		return false
	}

	tokenEpoch, err := strconv.ParseInt(epochStr, 10, 64)
	if err != nil {
		return false
	}
	currentEpoch := time.Now().Unix() / 86400
	// Allow current epoch and previous day epoch for continuous sessions around midnight UTC
	if tokenEpoch != currentEpoch && tokenEpoch != (currentEpoch-1) {
		return false
	}

	cfg := a.configMgr.Get()
	mac := hmac.New(sha256.New, []byte(cfg.Server.SessionSecret))
	mac.Write(fmt.Appendf(nil, "csrf:%s:%s", username, epochStr))
	expectedSig := mac.Sum(nil)

	actualSig, err := base64.RawURLEncoding.DecodeString(sigBase64)
	if err != nil {
		return false
	}

	return hmac.Equal(expectedSig, actualSig)
}

func (a *AuthService) SetSessionCookie(w http.ResponseWriter, r *http.Request, username string) {
	token := a.GenerateSessionToken(username)
	isTLS := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
		Secure:   isTLS,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *AuthService) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *AuthService) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if _, ok := a.ValidateSessionToken(cookie.Value); !ok {
			a.ClearSessionCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

func (a *AuthService) RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return a.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie(sessionCookieName)
		username, _ := a.ValidateSessionToken(cookie.Value)

		if a.GetUserRole(username) != "admin" {
			http.Error(w, "Forbidden: Administrator role required", http.StatusForbidden)
			return
		}

		next(w, r)
	})
}
