package main

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

type FlashStore struct {
	mu          sync.Mutex
	lastResults map[string]*ExecutionResult
	flashes     map[string]string
}

func NewFlashStore() *FlashStore {
	return &FlashStore{
		lastResults: make(map[string]*ExecutionResult),
		flashes:     make(map[string]string),
	}
}

func (s *FlashStore) SetResult(user string, res *ExecutionResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastResults[user] = res
}

func (s *FlashStore) PopResult(user string) *ExecutionResult {
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
	configMgr     *ConfigManager
	auth          *AuthService
	sshRunner     *SSHRunner
	store         *FlashStore
	i18n          *I18nManager
	loginTmpl     *template.Template
	dashboardTmpl *template.Template
}

func NewServer(cm *ConfigManager) (*Server, error) {
	loginTmpl, err := template.ParseFS(templateFS, "templates/login.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse login template: %w", err)
	}

	dashboardTmpl, err := template.ParseFS(templateFS, "templates/dashboard.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse dashboard template: %w", err)
	}

	auth := NewAuthService(cm)
	runner := NewSSHRunner(cm)
	store := NewFlashStore()
	i18n := NewI18nManager()

	return &Server{
		configMgr:     cm,
		auth:          auth,
		sshRunner:     runner,
		store:         store,
		i18n:          i18n,
		loginTmpl:     loginTmpl,
		dashboardTmpl: dashboardTmpl,
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

	// Auth routes
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("POST /login", s.handleLoginSubmit)
	mux.HandleFunc("POST /logout", s.handleLogout)

	// Protected routes
	mux.HandleFunc("GET /", s.auth.RequireAuth(s.handleDashboard))
	mux.HandleFunc("POST /run", s.auth.RequireAuth(s.handleRun))
	mux.HandleFunc("POST /reload", s.auth.RequireAuth(s.handleReload))
}

func (s *Server) handleSetLang(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	if lang != LangAR && lang != LangEN {
		lang = LangEN
	}
	http.SetCookie(w, &http.Cookie{
		Name:     langCookieName,
		Value:    lang,
		Path:     "/",
		MaxAge:   365 * 24 * 3600,
		SameSite: http.SameSiteLaxMode,
	})

	redirectURL := r.Referer()
	if redirectURL == "" || (!strings.HasPrefix(redirectURL, "/") && !strings.Contains(redirectURL, r.Host)) {
		redirectURL = "/"
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (s *Server) getSessionUser(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}
	user, _ := s.auth.ValidateSessionToken(cookie.Value)
	return user
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if user := s.getSessionUser(r); user != "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	lang := s.i18n.ResolveLanguage(r)
	otherLang, otherLabel := GetOtherLang(lang)

	data := struct {
		Error      string
		Lang       string
		Dir        string
		OtherLang  string
		OtherLabel string
		T          map[string]string
	}{
		Error:      "",
		Lang:       lang,
		Dir:        GetDir(lang),
		OtherLang:  otherLang,
		OtherLabel: otherLabel,
		T:          s.i18n.GetTranslations(lang),
	}
	_ = s.loginTmpl.Execute(w, data)
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	lang := s.i18n.ResolveLanguage(r)

	if !s.auth.CheckCredentials(username, password) {
		w.WriteHeader(http.StatusUnauthorized)
		otherLang, otherLabel := GetOtherLang(lang)
		data := struct {
			Error      string
			Lang       string
			Dir        string
			OtherLang  string
			OtherLabel string
			T          map[string]string
		}{
			Error:      s.i18n.T(lang, "invalid_credentials"),
			Lang:       lang,
			Dir:        GetDir(lang),
			OtherLang:  otherLang,
			OtherLabel: otherLabel,
			T:          s.i18n.GetTranslations(lang),
		}
		_ = s.loginTmpl.Execute(w, data)
		return
	}

	s.auth.SetSessionCookie(w, username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.ClearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	user := s.getSessionUser(r)
	cfg := s.configMgr.Get()

	lastRes := s.store.PopResult(user)
	flash := s.store.PopFlash(user)

	lang := s.i18n.ResolveLanguage(r)
	otherLang, otherLabel := GetOtherLang(lang)

	data := struct {
		Categories []NormalizedCategory
		LastResult *ExecutionResult
		Flash      string
		User       string
		HostCount  int
		Lang       string
		Dir        string
		OtherLang  string
		OtherLabel string
		T          map[string]string
	}{
		Categories: cfg.Categories,
		LastResult: lastRes,
		Flash:      flash,
		User:       user,
		HostCount:  len(cfg.Hosts),
		Lang:       lang,
		Dir:        GetDir(lang),
		OtherLang:  otherLang,
		OtherLabel: otherLabel,
		T:          s.i18n.GetTranslations(lang),
	}

	_ = s.dashboardTmpl.Execute(w, data)
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	buttonID := strings.TrimSpace(r.FormValue("button_id"))
	user := s.getSessionUser(r)

	cfg := s.configMgr.Get()
	btn, exists := cfg.ButtonsByID[buttonID]
	if !exists {
		s.store.SetResult(user, &ExecutionResult{
			ButtonID:     buttonID,
			ButtonLabel:  buttonID,
			Success:      false,
			ErrorDetails: fmt.Sprintf("Button %q not found in current configuration", buttonID),
			ExecutedAt:   time.Now(),
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	timeout := btn.Timeout
	if timeout <= 0 {
		timeout = cfg.Server.DefaultSSHTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+3)*time.Second)
	defer cancel()

	result := s.sshRunner.Execute(ctx, btn)
	s.store.SetResult(user, result)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	user := s.getSessionUser(r)
	lang := s.i18n.ResolveLanguage(r)
	if err := s.configMgr.Reload(); err != nil {
		s.store.SetFlash(user, fmt.Sprintf("%s: %v", s.i18n.T(lang, "config_reload_failed"), err))
	} else {
		cfg := s.configMgr.Get()
		s.store.SetFlash(user, fmt.Sprintf("%s (%d hosts, %d buttons).", s.i18n.T(lang, "config_reload_ok"), len(cfg.Hosts), len(cfg.ButtonsByID)))
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	manifestBytes, err := staticFS.ReadFile("static/manifest.json")
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(manifestBytes)
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	// r.URL.Path looks like /static/icon.svg
	relPath := strings.TrimPrefix(r.URL.Path, "/")
	file, err := staticFS.Open(relPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()

	if strings.HasSuffix(relPath, ".svg") {
		w.Header().Set("Content-Type", "image/svg+xml")
	} else if strings.HasSuffix(relPath, ".json") {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = io.Copy(w, file)
}
