package server

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"ssh_buttons/internal/auth"
	"ssh_buttons/internal/config"
	"ssh_buttons/internal/i18n"
	"ssh_buttons/internal/ssh"
	"ssh_buttons/web"
)

func render(w http.ResponseWriter, tmpl *template.Template, data any) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "base.html", data); err != nil {
		log.Printf("[ERROR] Template execution failed: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

func (s *Server) handleSetLang(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	if lang != i18n.LangAR && lang != i18n.LangEN {
		lang = i18n.LangEN
	}
	http.SetCookie(w, &http.Cookie{
		Name:     i18n.LangCookieName,
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

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	lang := s.i18n.ResolveLanguage(r)
	otherLang, otherLabel := i18n.GetOtherLang(lang)

	exampleContent, err := os.ReadFile("config.example.yml")
	var exampleYAML string
	if err == nil {
		exampleYAML = string(exampleContent)
	} else if raw, readErr := s.configMgr.ReadRawConfigFile(); readErr == nil {
		exampleYAML = raw
	}

	data := struct {
		Lang        string
		Dir         string
		OtherLang   string
		OtherLabel  string
		ExampleYAML string
		T           map[string]string
	}{
		Lang:        lang,
		Dir:         i18n.GetDir(lang),
		OtherLang:  otherLang,
		OtherLabel:  otherLabel,
		ExampleYAML: exampleYAML,
		T:           s.i18n.GetTranslations(lang),
	}

	render(w, s.docsTmpl, data)
}

func (s *Server) getSessionUser(r *http.Request) string {
	cookie, err := r.Cookie(auth.SessionCookieName)
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
	otherLang, otherLabel := i18n.GetOtherLang(lang)

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
		Dir:        i18n.GetDir(lang),
		OtherLang:  otherLang,
		OtherLabel: otherLabel,
		T:          s.i18n.GetTranslations(lang),
	}
	render(w, s.loginTmpl, data)
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB body limit
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ip := auth.GetClientIP(r)
	lang := s.i18n.ResolveLanguage(r)

	// Rate limiting: protect against brute-force attacks
	if !s.auth.AllowLogin(ip) {
		w.WriteHeader(http.StatusTooManyRequests)
		otherLang, otherLabel := i18n.GetOtherLang(lang)
		data := struct {
			Error      string
			Lang       string
			Dir        string
			OtherLang  string
			OtherLabel string
			T          map[string]string
		}{
			Error:      s.i18n.T(lang, "rate_limit_exceeded"),
			Lang:       lang,
			Dir:        i18n.GetDir(lang),
			OtherLang:  otherLang,
			OtherLabel: otherLabel,
			T:          s.i18n.GetTranslations(lang),
		}
		render(w, s.loginTmpl, data)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	if !s.auth.CheckCredentials(username, password) {
		s.auth.RecordLoginFailure(ip)
		w.WriteHeader(http.StatusUnauthorized)
		otherLang, otherLabel := i18n.GetOtherLang(lang)
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
			Dir:        i18n.GetDir(lang),
			OtherLang:  otherLang,
			OtherLabel: otherLabel,
			T:          s.i18n.GetTranslations(lang),
		}
		render(w, s.loginTmpl, data)
		return
	}

	s.auth.RecordLoginSuccess(ip)
	s.auth.SetSessionCookie(w, r, username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	user := s.getSessionUser(r)
	if user != "" {
		csrfToken := r.FormValue("csrf_token")
		if !s.auth.ValidateCSRFToken(user, csrfToken) {
			http.Error(w, "Forbidden: Invalid or missing CSRF token", http.StatusForbidden)
			return
		}
	}

	s.auth.ClearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	user := s.getSessionUser(r)
	role := s.auth.GetUserRole(user)
	cfg := s.configMgr.Get()

	lastRes := s.store.PopResult(user)
	flash := s.store.PopFlash(user)

	lang := s.i18n.ResolveLanguage(r)
	otherLang, otherLabel := i18n.GetOtherLang(lang)

	data := struct {
		Categories []config.NormalizedCategory
		LastResult *ssh.ExecutionResult
		Flash      string
		User       string
		Role       string
		IsAdmin    bool
		HostCount  int
		CSRFToken  string
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
		Role:       role,
		IsAdmin:    role == "admin",
		HostCount:  len(cfg.Hosts),
		CSRFToken:  s.auth.GenerateCSRFToken(user),
		Lang:       lang,
		Dir:        i18n.GetDir(lang),
		OtherLang:  otherLang,
		OtherLabel: otherLabel,
		T:          s.i18n.GetTranslations(lang),
	}

	render(w, s.dashboardTmpl, data)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	user := s.getSessionUser(r)
	lang := s.i18n.ResolveLanguage(r)
	otherLang, otherLabel := i18n.GetOtherLang(lang)

	content, err := s.configMgr.ReadRawConfigFile()
	if err != nil {
		content = "# Error reading config file: " + err.Error()
	}

	data := struct {
		YAML       string
		Error      string
		CSRFToken  string
		Lang       string
		Dir        string
		OtherLang  string
		OtherLabel string
		T          map[string]string
	}{
		YAML:       content,
		Error:      "",
		CSRFToken:  s.auth.GenerateCSRFToken(user),
		Lang:       lang,
		Dir:        i18n.GetDir(lang),
		OtherLang:  otherLang,
		OtherLabel: otherLabel,
		T:          s.i18n.GetTranslations(lang),
	}

	render(w, s.configTmpl, data)
}

func (s *Server) handleConfigSave(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request: Request body exceeds maximum permitted size", http.StatusBadRequest)
		return
	}

	user := s.getSessionUser(r)
	csrfToken := r.FormValue("csrf_token")
	if !s.auth.ValidateCSRFToken(user, csrfToken) {
		http.Error(w, "Forbidden: Invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	rawYaml := r.FormValue("yaml")
	if rawYaml == "" {
		rawYaml = r.FormValue("config_yaml")
	}
	lang := s.i18n.ResolveLanguage(r)

	if err := s.configMgr.SaveConfigFile([]byte(rawYaml)); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		otherLang, otherLabel := i18n.GetOtherLang(lang)
		data := struct {
			YAML       string
			Error      string
			CSRFToken  string
			Lang       string
			Dir        string
			OtherLang  string
			OtherLabel string
			T          map[string]string
		}{
			YAML:       rawYaml,
			Error:      fmt.Sprintf("%s: %v", s.i18n.T(lang, "yaml_syntax_error"), err),
			CSRFToken:  s.auth.GenerateCSRFToken(user),
			Lang:       lang,
			Dir:        i18n.GetDir(lang),
			OtherLang:  otherLang,
			OtherLabel: otherLabel,
			T:          s.i18n.GetTranslations(lang),
		}
		render(w, s.configTmpl, data)
		return
	}

	s.store.SetFlash(user, s.i18n.T(lang, "config_saved"))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	user := s.getSessionUser(r)
	csrfToken := r.FormValue("csrf_token")
	if !s.auth.ValidateCSRFToken(user, csrfToken) {
		http.Error(w, "Forbidden: Invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	buttonID := strings.TrimSpace(r.FormValue("button_id"))

	cfg := s.configMgr.Get()
	btn, exists := cfg.ButtonsByID[buttonID]
	if !exists {
		s.store.SetResult(user, &ssh.ExecutionResult{
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
		timeout = cfg.Server.Timeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+3)*time.Second)
	defer cancel()

	result := s.sshRunner.Execute(ctx, btn)
	s.store.SetResult(user, result)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	user := s.getSessionUser(r)
	csrfToken := r.FormValue("csrf_token")
	if !s.auth.ValidateCSRFToken(user, csrfToken) {
		http.Error(w, "Forbidden: Invalid or missing CSRF token", http.StatusForbidden)
		return
	}

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
	manifestBytes, err := web.StaticFS.ReadFile("static/manifest.json")
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
	file, err := web.StaticFS.Open(relPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()

	if strings.HasSuffix(relPath, ".svg") {
		w.Header().Set("Content-Type", "image/svg+xml")
	} else if strings.HasSuffix(relPath, ".json") {
		w.Header().Set("Content-Type", "application/json")
	} else if strings.HasSuffix(relPath, ".css") {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = io.Copy(w, file)
}

// SecurityHeadersMiddleware adds defensive HTTP security headers to all responses
