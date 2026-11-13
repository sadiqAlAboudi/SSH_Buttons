package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupTestServer(t *testing.T) (*Server, *ConfigManager, string) {
	t.Helper()
	yamlContent := `
users:
  - user: "admin"
    pass: "adminpass"
    role: "admin"
  - user: "operator"
    pass: "operatorpass"
    role: "operator"

hosts:
  test_host:
    name: "Test Host"
    host: "127.0.0.1"
    user: "root"
    pass: "dummy"

categories:
  - name: "Ops"
    host: "test_host"
    buttons:
      - name: "Ping"
        cmd: "echo pong"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	cm, err := NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to initialize ConfigManager: %v", err)
	}

	server, err := NewServer(cm)
	if err != nil {
		t.Fatalf("Failed to initialize Server: %v", err)
	}

	return server, cm, configPath
}

func TestCSRFTokenGenerationAndValidation(t *testing.T) {
	_, cm, _ := setupTestServer(t)
	auth := NewAuthService(cm)

	userA := "admin"
	userB := "operator"

	tokenA := auth.GenerateCSRFToken(userA)
	if tokenA == "" {
		t.Fatal("Expected non-empty CSRF token")
	}

	// 1. Valid token for userA
	if !auth.ValidateCSRFToken(userA, tokenA) {
		t.Errorf("ValidateCSRFToken failed for valid user and token")
	}

	// 2. Token from userA should NOT validate for userB (prevents cross-user CSRF)
	if auth.ValidateCSRFToken(userB, tokenA) {
		t.Errorf("ValidateCSRFToken allowed token from userA to be used by userB")
	}

	// 3. Tampered token
	if auth.ValidateCSRFToken(userA, tokenA+"tampered") {
		t.Errorf("ValidateCSRFToken accepted tampered token")
	}

	// 4. Empty token or empty user
	if auth.ValidateCSRFToken("", tokenA) || auth.ValidateCSRFToken(userA, "") {
		t.Errorf("ValidateCSRFToken accepted empty user or empty token")
	}
}

func TestLoginRateLimiter(t *testing.T) {
	limiter := NewLoginRateLimiter(5, 1*time.Minute)
	ip := "192.168.1.50"

	// First 5 attempts should be allowed
	for i := 0; i < 5; i++ {
		if !limiter.Allow(ip) {
			t.Fatalf("Expected attempt %d to be allowed", i+1)
		}
		limiter.RecordFailure(ip)
	}

	// 6th attempt should be blocked
	if limiter.Allow(ip) {
		t.Errorf("Expected 6th attempt to be rate limited, but Allow returned true")
	}

	// A different IP should NOT be affected
	differentIP := "192.168.1.99"
	if !limiter.Allow(differentIP) {
		t.Errorf("Expected different IP to be allowed despite other IP being blocked")
	}

	// Successful login clears history
	limiter.RecordSuccess(ip)
	if !limiter.Allow(ip) {
		t.Errorf("Expected IP to be allowed after RecordSuccess")
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	guarded := SecurityHeadersMiddleware(dummyHandler)
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	guarded.ServeHTTP(rr, req)

	expectedHeaders := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}

	for header, expectedValue := range expectedHeaders {
		actual := rr.Header().Get(header)
		if actual != expectedValue {
			t.Errorf("Header %q: expected %q, got %q", header, expectedValue, actual)
		}
	}

	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("Expected CSP to include frame-ancestors 'none', got %q", csp)
	}
}

func TestHandlers_CSRFEnforcementOnPostEndpoints(t *testing.T) {
	server, _, _ := setupTestServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	sessionToken := server.auth.GenerateSessionToken("admin")
	csrfToken := server.auth.GenerateCSRFToken("admin")

	endpoints := []struct {
		name        string
		path        string
		data        url.Values
		validStatus int
	}{
		{
			name:        "Run Button",
			path:        "/run",
			data:        url.Values{"button_id": {"ops-ping"}},
			validStatus: http.StatusSeeOther,
		},
		{
			name:        "Reload Config",
			path:        "/reload",
			data:        url.Values{},
			validStatus: http.StatusSeeOther,
		},
		{
			name:        "Logout",
			path:        "/logout",
			data:        url.Values{},
			validStatus: http.StatusSeeOther,
		},
	}

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			// 1. Without CSRF token: must fail with 403 Forbidden
			noCsrfData := make(url.Values)
			for k, v := range ep.data {
				noCsrfData[k] = v
			}

			reqNoCSRF := httptest.NewRequest("POST", ep.path, strings.NewReader(noCsrfData.Encode()))
			reqNoCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			reqNoCSRF.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
			rrNoCSRF := httptest.NewRecorder()

			mux.ServeHTTP(rrNoCSRF, reqNoCSRF)
			if rrNoCSRF.Code != http.StatusForbidden {
				t.Errorf("Expected 403 Forbidden when CSRF token is missing for %s, got %d", ep.path, rrNoCSRF.Code)
			}

			// 2. With valid CSRF token: must succeed
			withCsrfData := make(url.Values)
			for k, v := range ep.data {
				withCsrfData[k] = v
			}
			withCsrfData.Set("csrf_token", csrfToken)

			reqWithCSRF := httptest.NewRequest("POST", ep.path, strings.NewReader(withCsrfData.Encode()))
			reqWithCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			reqWithCSRF.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
			rrWithCSRF := httptest.NewRecorder()

			mux.ServeHTTP(rrWithCSRF, reqWithCSRF)
			if rrWithCSRF.Code != ep.validStatus {
				t.Errorf("Expected %d with valid CSRF token for %s, got %d (body: %s)", ep.validStatus, ep.path, rrWithCSRF.Code, rrWithCSRF.Body.String())
			}
		})
	}
}

func TestHandlers_LoginRateLimitEnforcement(t *testing.T) {
	server, _, _ := setupTestServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	ip := "10.10.10.10:45123"

	// 5 failed login attempts
	for i := 1; i <= 5; i++ {
		formData := url.Values{
			"username": {"admin"},
			"password": {"wrong-password"},
		}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()

		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("Expected attempt %d to return 401 Unauthorized, got %d", i, rr.Code)
		}
	}

	// 6th attempt should be blocked with 429 Too Many Requests
	formData := url.Values{
		"username": {"admin"},
		"password": {"adminpass"}, // Even with right password, should be blocked by rate limiter!
	}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ip
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("Expected 6th attempt to return 429 Too Many Requests, got %d", rr.Code)
	}
}

func TestHandlers_MaxBodySizeCap(t *testing.T) {
	server, _, _ := setupTestServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	sessionToken := server.auth.GenerateSessionToken("admin")
	csrfToken := server.auth.GenerateCSRFToken("admin")

	// Create a payload larger than 1MB (e.g. 1.5MB)
	hugeString := strings.Repeat("A", 1500*1024)
	formData := url.Values{
		"config_yaml": {hugeString},
		"csrf_token":  {csrfToken},
	}

	req := httptest.NewRequest("POST", "/config", bytes.NewReader([]byte(formData.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	// MaxBytesReader causes ParseForm to fail with request body too large (Status 400 Bad Request)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request when exceeding 1MB body limit, got %d", rr.Code)
	}
}

func TestDocsEndpoint(t *testing.T) {
	server, _, _ := setupTestServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	// 1. Unauthenticated request to /docs should redirect to /login
	reqUnauth := httptest.NewRequest("GET", "/docs", nil)
	rrUnauth := httptest.NewRecorder()
	mux.ServeHTTP(rrUnauth, reqUnauth)
	if rrUnauth.Code != http.StatusSeeOther || rrUnauth.Header().Get("Location") != "/login" {
		t.Errorf("Expected 303 redirect to /login, got code=%d location=%s", rrUnauth.Code, rrUnauth.Header().Get("Location"))
	}

	sessionToken := server.auth.GenerateSessionToken("admin")

	// 2. Authenticated English request
	reqEN := httptest.NewRequest("GET", "/docs", nil)
	reqEN.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	reqEN.AddCookie(&http.Cookie{Name: langCookieName, Value: "en"})
	rrEN := httptest.NewRecorder()
	mux.ServeHTTP(rrEN, reqEN)
	if rrEN.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /docs, got %d", rrEN.Code)
	}
	bodyEN := rrEN.Body.String()
	if !strings.Contains(bodyEN, `dir="ltr"`) || !strings.Contains(bodyEN, "Documentation &amp; Manual") && !strings.Contains(bodyEN, "Documentation & Manual") {
		t.Errorf("Expected LTR and English title in docs response, got body snippet: %s", bodyEN[:300])
	}
	if !strings.Contains(bodyEN, "Cisco Switch") || !strings.Contains(bodyEN, "MikroTik Gateway") {
		t.Errorf("Expected vendor recipes in English docs")
	}

	// 3. Authenticated Arabic request
	reqAR := httptest.NewRequest("GET", "/docs", nil)
	reqAR.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	reqAR.AddCookie(&http.Cookie{Name: langCookieName, Value: "ar"})
	rrAR := httptest.NewRecorder()
	mux.ServeHTTP(rrAR, reqAR)
	if rrAR.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for Arabic /docs, got %d", rrAR.Code)
	}
	bodyAR := rrAR.Body.String()
	if !strings.Contains(bodyAR, `dir="rtl"`) || !strings.Contains(bodyAR, "دليل الإعداد والتوثيق") {
		t.Errorf("Expected RTL and Arabic title in docs response, got body snippet: %s", bodyAR[:300])
	}
	if !strings.Contains(bodyAR, "الأجهزة البعيدة") {
		t.Errorf("Expected Arabic section headers in docs response")
	}
}
