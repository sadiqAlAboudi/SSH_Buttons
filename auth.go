package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "ssh_buttons_session"
	sessionDuration   = 24 * time.Hour
)

type AuthService struct {
	configMgr *ConfigManager
}

func NewAuthService(cm *ConfigManager) *AuthService {
	return &AuthService{configMgr: cm}
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
	expectedMac.Write([]byte(fmt.Sprintf("%s:%s", username, expiresAtStr)))
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

func (a *AuthService) SetSessionCookie(w http.ResponseWriter, username string) {
	token := a.GenerateSessionToken(username)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
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
