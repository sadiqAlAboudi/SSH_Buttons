package server

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

	"ssh_buttons/internal/auth"
	"ssh_buttons/internal/config"
	"ssh_buttons/internal/i18n"
	"ssh_buttons/internal/ssh"
)

func setupTestServer(t *testing.T) (*Server, *config.ConfigManager, string) {
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

	cm, err := config.NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to initialize config.ConfigManager: %v", err)
	}

	server, err := NewServer(cm)
	if err != nil {
		t.Fatalf("Failed to initialize Server: %v", err)
	}

	return server, cm, configPath
}

func TestCSRFTokenGenerationAndValidation(t *testing.T) {
	_, cm, _ := setupTestServer(t)
	authSvc := auth.NewAuthService(cm)

	userA := "admin"
	userB := "operator"

	tokenA := authSvc.GenerateCSRFToken(userA)
	if tokenA == "" {
		t.Fatal("Expected non-empty CSRF token")
	}

	// 1. Valid token for userA
	if !authSvc.ValidateCSRFToken(userA, tokenA) {
		t.Errorf("ValidateCSRFToken failed for valid user and token")
	}

	// 2. Token from userA should NOT validate for userB (prevents cross-user CSRF)
	if authSvc.ValidateCSRFToken(userB, tokenA) {
		t.Errorf("ValidateCSRFToken allowed token from userA to be used by userB")
	}

	// 3. Tampered token
	if authSvc.ValidateCSRFToken(userA, tokenA+"tampered") {
		t.Errorf("ValidateCSRFToken accepted tampered token")
	}

	// 4. Empty token or empty user
	if authSvc.ValidateCSRFToken("", tokenA) || authSvc.ValidateCSRFToken(userA, "") {
		t.Errorf("ValidateCSRFToken accepted empty user or empty token")
	}
}

func TestLoginRateLimiter(t *testing.T) {
	limiter := auth.NewLoginRateLimiter(5, 1*time.Minute)
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
			reqNoCSRF.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
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
			reqWithCSRF.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
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
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
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
	reqEN.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
	reqEN.AddCookie(&http.Cookie{Name: i18n.LangCookieName, Value: "en"})
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
	reqAR.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
	reqAR.AddCookie(&http.Cookie{Name: i18n.LangCookieName, Value: "ar"})
	rrAR := httptest.NewRecorder()
	mux.ServeHTTP(rrAR, reqAR)
	if rrAR.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for Arabic /docs, got %d", rrAR.Code)
	}
	bodyAR := rrAR.Body.String()
	if !strings.Contains(bodyAR, `dir="rtl"`) || !strings.Contains(bodyAR, "دليل الاستخدام وتهيئة النظام") {
		t.Errorf("Expected RTL and refined Arabic title in docs response, got body snippet: %s", bodyAR[:300])
	}
	if !strings.Contains(bodyAR, "الخوادم وأجهزة الشبكة") {
		t.Errorf("Expected refined Arabic section headers in docs response")
	}
	// Verify that code snippets strictly maintain LTR direction via linked app.css
	reqCSS := httptest.NewRequest("GET", "/static/app.css", nil)
	rrCSS := httptest.NewRecorder()
	mux.ServeHTTP(rrCSS, reqCSS)
	if rrCSS.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /static/app.css, got %d", rrCSS.Code)
	}
	if !strings.Contains(rrCSS.Body.String(), "direction: ltr !important") {
		t.Errorf("Expected app.css to enforce LTR direction on code blocks")
	}
}

func TestResponsiveHamburgerMenu(t *testing.T) {
	server, _, _ := setupTestServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	sessionToken := server.auth.GenerateSessionToken("admin")

	endpoints := []string{"/", "/config", "/docs"}

	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			req := httptest.NewRequest("GET", endpoint, nil)
			req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("Expected 200 OK for %s, got %d", endpoint, rr.Code)
			}

			body := rr.Body.String()
			requiredElements := []string{
				`id="hamburgerBtn"`,
				`class="btn-hamburger"`,
				`id="headerActions"`,
				`id="navBackdrop"`,
				`class="nav-backdrop"`,
				`/static/app.css`,
			}

			for _, elem := range requiredElements {
				if !strings.Contains(body, elem) {
					t.Errorf("Endpoint %s missing expected responsive menu element: %s", endpoint, elem)
				}
			}
		})
	}

	// Verify app.css contains the responsive media queries
	reqCSS := httptest.NewRequest("GET", "/static/app.css", nil)
	rrCSS := httptest.NewRecorder()
	mux.ServeHTTP(rrCSS, reqCSS)
	if rrCSS.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /static/app.css, got %d", rrCSS.Code)
	}
	if !strings.Contains(rrCSS.Header().Get("Content-Type"), "text/css") {
		t.Errorf("Expected Content-Type text/css, got %s", rrCSS.Header().Get("Content-Type"))
	}
	if !strings.Contains(rrCSS.Body.String(), "@media (max-width: 768px)") {
		t.Errorf("Expected app.css to define @media (max-width: 768px)")
	}
}

func TestDashboardButtonsRendered(t *testing.T) {
	server, _, _ := setupTestServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	sessionToken := server.auth.GenerateSessionToken("admin")

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Verify categories, button labels, and commands render into the HTML
	expectedStrings := []string{
		"Ops",
		"Ping",
		"echo pong",
		"test_host",
		"btn-act",
	}

	for _, str := range expectedStrings {
		if !strings.Contains(body, str) {
			t.Errorf("Dashboard response missing expected rendered element %q", str)
		}
	}
}

func TestConfigEditorContentAndSave(t *testing.T) {
	server, _, _ := setupTestServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	sessionToken := server.auth.GenerateSessionToken("admin")

	// 1. GET /config should populate the textarea with config YAML
	req := httptest.NewRequest("GET", "/config", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /config, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, `<textarea id="configYaml" name="yaml"`) {
		t.Errorf("Expected config editor textarea with name='yaml'")
	}
	if !strings.Contains(body, "test_host:") || !strings.Contains(body, "echo pong") {
		t.Errorf("Expected config editor textarea to be populated with current config YAML, got body: %s", body)
	}

	// 2. POST /config with new YAML should successfully update and redirect
	csrfToken := server.auth.GenerateCSRFToken("admin")
	newYAML := `users:
  - user: "admin"
    pass: "adminpass"
    role: "admin"
hosts:
  prod_host:
    name: "Production Host"
    host: "10.0.0.99"
    user: "admin"
    pass: "pass"
categories:
  - name: "Production Actions"
    description: "High impact operations"
    host: "prod_host"
    buttons:
      - name: "Restart Nginx"
        cmd: "systemctl restart nginx"
        warning: true
`
	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	form.Set("yaml", newYAML)

	reqSave := httptest.NewRequest("POST", "/config", strings.NewReader(form.Encode()))
	reqSave.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqSave.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
	rrSave := httptest.NewRecorder()
	mux.ServeHTTP(rrSave, reqSave)

	if rrSave.Code != http.StatusSeeOther {
		t.Fatalf("Expected 303 See Other after save, got %d. Body: %s", rrSave.Code, rrSave.Body.String())
	}

	// 3. Verify dashboard now renders new category, description, and button
	reqDash := httptest.NewRequest("GET", "/", nil)
	reqDash.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
	rrDash := httptest.NewRecorder()
	mux.ServeHTTP(rrDash, reqDash)

	if rrDash.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /, got %d", rrDash.Code)
	}

	dashBody := rrDash.Body.String()
	newStrings := []string{
		"Production Actions",
		"High impact operations",
		"Restart Nginx",
		"systemctl restart nginx",
		"prod_host",
	}

	for _, str := range newStrings {
		if !strings.Contains(dashBody, str) {
			t.Errorf("Dashboard missing newly saved element %q", str)
		}
	}
}

func TestDashboardLastResultRendering(t *testing.T) {
	server, _, _ := setupTestServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	sessionToken := server.auth.GenerateSessionToken("admin")

	// Put a failed result with ErrorDetails and DiagnosticHint in FlashStore
	failedResult := &ssh.ExecutionResult{
		ButtonID:       "ping_btn",
		ButtonLabel:    "Ping Host",
		HostName:       "Test Host",
		HostAddress:    "127.0.0.1:22",
		Command:        "ping -c 1 8.8.8.8",
		Success:        false,
		ExitCode:       2,
		Duration:       250 * time.Millisecond,
		Stderr:         "Network unreachable",
		ErrorDetails:   "Execution failed: channel open: rejected",
		DiagnosticHint: "This device may not support non-interactive 'exec' commands. Enable 'pty: true' in config.yml for this host or button.",
		ExecutedAt:     time.Now(),
	}
	server.store.SetResult("admin", failedResult)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK when rendering dashboard with failed result, got %d", rr.Code)
	}

	body := rr.Body.String()
	requiredSnippets := []string{
		"Execution failed: channel open: rejected",
		"Diagnostic Hint:",
		"pty: true",
		"Network unreachable",
		"pill-failed",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(body, snippet) {
			t.Errorf("Expected dashboard to contain %q, but got body:\n%s", snippet, body)
		}
	}
}

func TestGUIConfigTabsRendered(t *testing.T) {
	server, _, _ := setupTestServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	sessionToken := server.auth.GenerateSessionToken("admin")

	req := httptest.NewRequest("GET", "/config", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /config, got %d", rr.Code)
	}

	body := rr.Body.String()
	expectedElements := []string{
		`id="tabBtnCategories"`,
		`id="tabBtnHosts"`,
		`id="tabBtnUsers"`,
		`id="tabBtnYaml"`,
		`id="tabContentCategories"`,
		`id="tabContentHosts"`,
		`id="tabContentUsers"`,
		`id="tabContentYaml"`,
		`id="dlgUser"`,
		`id="dlgHost"`,
		`id="dlgCategory"`,
		`id="dlgButton"`,
		`id="dlgDelete"`,
		`id="rawConfigJson"`,
		`id="configMode"`,
		`id="configJson"`,
	}

	for _, elem := range expectedElements {
		if !strings.Contains(body, elem) {
			t.Errorf("Config page missing expected GUI element %q", elem)
		}
	}
}

func TestGUIConfigSaveStructured_AddUserAndHost(t *testing.T) {
	server, cm, _ := setupTestServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	sessionToken := server.auth.GenerateSessionToken("admin")
	csrfToken := server.auth.GenerateCSRFToken("admin")

	// Prepare structured JSON payload adding an operator user and a new host
	guiPayload := `{
		"users": [
			{"user": "admin", "pass": "adminpass", "role": "admin"},
			{"user": "tech_lead", "pass": "securePlainPass123", "role": "operator"}
		],
		"hosts": {
			"test_host": {"name": "Test Host", "host": "127.0.0.1", "port": 22, "user": "root"},
			"cloud_db": {"name": "Database Cluster", "host": "10.0.1.5", "port": 2222, "user": "postgres", "key": "./keys/id_rsa"}
		},
		"categories": [
			{
				"name": "Database Ops",
				"description": "Routine DB health checks",
				"host": "cloud_db",
				"buttons": [
					{"name": "Check DB Connections", "cmd": "select count(*) from pg_stat_activity;", "style": "primary"}
				]
			}
		]
	}`

	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	form.Set("config_mode", "gui")
	form.Set("config_json", guiPayload)

	reqSave := httptest.NewRequest("POST", "/config", strings.NewReader(form.Encode()))
	reqSave.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqSave.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
	rrSave := httptest.NewRecorder()
	mux.ServeHTTP(rrSave, reqSave)

	if rrSave.Code != http.StatusSeeOther {
		t.Fatalf("Expected 303 redirect after saving structured GUI config, got %d. Body: %s", rrSave.Code, rrSave.Body.String())
	}

	// Verify the updated in-memory configuration
	cfg := cm.Get()
	if len(cfg.Users) != 2 {
		t.Fatalf("Expected 2 users, got %d", len(cfg.Users))
	}

	newU, ok := cfg.UsersByUsername["tech_lead"]
	if !ok {
		t.Fatalf("Expected user 'tech_lead' to exist in config")
	}
	if newU.Role != "operator" {
		t.Errorf("Expected role 'operator', got %q", newU.Role)
	}
	// Verify that password was automatically hashed with bcrypt
	if !strings.HasPrefix(newU.Password, "$2a$") {
		t.Errorf("Expected password to be bcrypt hashed, got %q", newU.Password)
	}
	// Verify user can successfully authenticate with plain text password
	if !server.auth.CheckCredentials("tech_lead", "securePlainPass123") {
		t.Errorf("Expected checkCredentials to succeed with plain password against bcrypt hash")
	}

	// Verify host and category button
	if _, ok := cfg.Hosts["cloud_db"]; !ok {
		t.Errorf("Expected host 'cloud_db' in config")
	}
	if len(cfg.Categories) != 1 || cfg.Categories[0].Name != "Database Ops" {
		t.Errorf("Expected category 'Database Ops', got %+v", cfg.Categories)
	}
	if len(cfg.Categories[0].Buttons) != 1 || cfg.Categories[0].Buttons[0].Label != "Check DB Connections" {
		t.Errorf("Expected button 'Check DB Connections', got %+v", cfg.Categories[0].Buttons)
	}
}

func TestGUIConfigSaveStructured_AdminSafeguard(t *testing.T) {
	server, _, _ := setupTestServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	sessionToken := server.auth.GenerateSessionToken("admin")
	csrfToken := server.auth.GenerateCSRFToken("admin")

	// Payload with only an operator and NO admin account
	noAdminPayload := `{
		"users": [
			{"user": "operator1", "pass": "somepass", "role": "operator"}
		],
		"hosts": {},
		"categories": []
	}`

	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	form.Set("config_mode", "gui")
	form.Set("config_json", noAdminPayload)

	reqSave := httptest.NewRequest("POST", "/config", strings.NewReader(form.Encode()))
	reqSave.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqSave.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionToken})
	rrSave := httptest.NewRecorder()
	mux.ServeHTTP(rrSave, reqSave)

	if rrSave.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request when saving without admin user, got %d", rrSave.Code)
	}

	body := rrSave.Body.String()
	if !strings.Contains(body, "admin") {
		t.Errorf("Expected error banner mentioning 'admin', got body: %s", body)
	}
}

