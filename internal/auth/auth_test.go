package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ssh_buttons/internal/config"

	"golang.org/x/crypto/bcrypt"
)

func TestAuthCredentialsAndTokens(t *testing.T) {
	// Generate a bcrypt password
	hashed, err := bcrypt.GenerateFromPassword([]byte("secretbcrypt"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate bcrypt: %v", err)
	}

	t.Setenv("SESSION_SECRET", "super-secret-signing-key")

	yamlContent := `
users:
  - user: "sysadmin"
    pass: "` + string(hashed) + `"
    role: "admin"
  - user: "operator_bob"
    pass: "plainbobpassword"
    role: "operator"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write temp config: %v", err)
	}

	cm, err := config.NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	auth := NewAuthService(cm)

	// Test valid credentials for admin
	if !auth.CheckCredentials("sysadmin", "secretbcrypt") {
		t.Errorf("CheckCredentials failed with valid bcrypt password")
	}
	if role := auth.GetUserRole("sysadmin"); role != "admin" {
		t.Errorf("Expected role 'admin' for sysadmin, got %s", role)
	}

	// Test valid credentials for operator
	if !auth.CheckCredentials("operator_bob", "plainbobpassword") {
		t.Errorf("CheckCredentials failed with valid plain password for operator")
	}
	if role := auth.GetUserRole("operator_bob"); role != "operator" {
		t.Errorf("Expected role 'operator' for operator_bob, got %s", role)
	}

	// Test invalid credentials
	if auth.CheckCredentials("sysadmin", "wrongpassword") {
		t.Errorf("CheckCredentials succeeded with wrong password")
	}
	if auth.CheckCredentials("wronguser", "secretbcrypt") {
		t.Errorf("CheckCredentials succeeded with wrong username")
	}

	// Test token generation & validation
	token := auth.GenerateSessionToken("sysadmin")
	user, valid := auth.ValidateSessionToken(token)
	if !valid || user != "sysadmin" {
		t.Errorf("ValidateSessionToken failed for freshly generated token: got %s, %v", user, valid)
	}

	// Test tampered token
	tampered := token + "tampered"
	if _, valid := auth.ValidateSessionToken(tampered); valid {
		t.Errorf("ValidateSessionToken accepted tampered token")
	}

	// Test RequireAdmin middleware
	adminHandlerCalled := false
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminHandlerCalled = true
		w.WriteHeader(http.StatusOK)
	})
	guarded := auth.RequireAdmin(dummyHandler)

	// Operator should be forbidden (403)
	opToken := auth.GenerateSessionToken("operator_bob")
	reqOp := httptest.NewRequest("GET", "/config", nil)
	reqOp.AddCookie(&http.Cookie{Name: SessionCookieName, Value: opToken})
	rrOp := httptest.NewRecorder()
	guarded.ServeHTTP(rrOp, reqOp)
	if rrOp.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for operator accessing admin route, got %d", rrOp.Code)
	}

	// Admin should be allowed (200)
	reqAdmin := httptest.NewRequest("GET", "/config", nil)
	reqAdmin.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	rrAdmin := httptest.NewRecorder()
	guarded.ServeHTTP(rrAdmin, reqAdmin)
	if rrAdmin.Code != http.StatusOK || !adminHandlerCalled {
		t.Errorf("Expected 200 OK for admin accessing admin route, got %d (called=%v)", rrAdmin.Code, adminHandlerCalled)
	}
}

func TestLoginRateLimiterMemoryCleanup(t *testing.T) {
	// Limiter with short window
	limiter := NewLoginRateLimiter(3, 10*time.Millisecond)
	ip := "192.0.2.1"

	limiter.RecordFailure(ip)
	limiter.RecordFailure(ip)

	// Wait for window to expire
	time.Sleep(20 * time.Millisecond)

	// Allow should clean up expired attempts
	if !limiter.Allow(ip) {
		t.Errorf("Expected Allow to return true after window expiry")
	}

	// Verify that the IP entry was deleted from memory to prevent leaks
	limiter.mu.Lock()
	_, exists := limiter.attempts[ip]
	limiter.mu.Unlock()

	if exists {
		t.Errorf("Expected IP %q to be deleted from attempts map after all attempts expired", ip)
	}
}
