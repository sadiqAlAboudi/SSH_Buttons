package server

import (
	"fmt"
	"html/template"
	"net/http"
	"sync"

	"ssh_buttons/internal/auth"
	"ssh_buttons/internal/config"
	"ssh_buttons/internal/i18n"
	"ssh_buttons/internal/ssh"
	"ssh_buttons/web"
)

type FlashStore struct {
	mu          sync.Mutex
	lastResults map[string]*ssh.ExecutionResult
	flashes     map[string]string
}

func NewFlashStore() *FlashStore {
	return &FlashStore{
		lastResults: make(map[string]*ssh.ExecutionResult),
		flashes:     make(map[string]string),
	}
}

func (s *FlashStore) SetResult(user string, res *ssh.ExecutionResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastResults[user] = res
}

func (s *FlashStore) PopResult(user string) *ssh.ExecutionResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := s.lastResults[user]
	delete(s.lastResults, user)
	return res
}

func (s *FlashStore) SetFlash(user, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flashes[user] = message
}

func (s *FlashStore) PopFlash(user string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	msg := s.flashes[user]
	delete(s.flashes, user)
	return msg
}

type Server struct {
	configMgr     *config.ConfigManager
	auth          *auth.AuthService
	sshRunner     *ssh.SSHRunner
	store         *FlashStore
	i18n          *i18n.I18nManager
	loginTmpl     *template.Template
	dashboardTmpl *template.Template
	configTmpl    *template.Template
	docsTmpl      *template.Template
}

func parseTemplate(childPage string) (*template.Template, error) {
	return template.ParseFS(web.TemplateFS, "templates/base.html", "templates/"+childPage)
}

func NewServer(cm *config.ConfigManager) (*Server, error) {
	loginTmpl, err := parseTemplate("login.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse login template: %w", err)
	}

	dashboardTmpl, err := parseTemplate("dashboard.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse dashboard template: %w", err)
	}

	configTmpl, err := parseTemplate("config.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse config template: %w", err)
	}

	docsTmpl, err := parseTemplate("docs.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse docs template: %w", err)
	}

	authService := auth.NewAuthService(cm)
	runner := ssh.NewSSHRunner(cm)
	store := NewFlashStore()
	i18nManager := i18n.NewI18nManager()

	return &Server{
		configMgr:     cm,
		auth:          authService,
		sshRunner:     runner,
		store:         store,
		i18n:          i18nManager,
		loginTmpl:     loginTmpl,
		dashboardTmpl: dashboardTmpl,
		configTmpl:    configTmpl,
		docsTmpl:      docsTmpl,
	}, nil
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	// Static assets and manifest
	mux.HandleFunc("GET /manifest.json", s.handleManifest)
	mux.HandleFunc("GET /static/", s.handleStatic)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Language switcher
	mux.HandleFunc("GET /set-lang", s.handleSetLang)

	// Documentation
	mux.HandleFunc("GET /docs", s.auth.RequireAuth(s.handleDocs))

	// Auth routes
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("POST /login", s.handleLoginSubmit)
	mux.HandleFunc("POST /logout", s.handleLogout)

	// Protected routes
	mux.HandleFunc("GET /", s.auth.RequireAuth(s.handleDashboard))
	mux.HandleFunc("POST /run", s.auth.RequireAuth(s.handleRun))
	mux.HandleFunc("POST /reload", s.auth.RequireAdmin(s.handleReload))
	mux.HandleFunc("GET /config", s.auth.RequireAdmin(s.handleConfig))
	mux.HandleFunc("POST /config", s.auth.RequireAdmin(s.handleConfigSave))
}

// SecurityHeadersMiddleware adds defensive HTTP security headers to all responses
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none';")
		next.ServeHTTP(w, r)
	})
}
