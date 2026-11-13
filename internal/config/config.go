package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type UserConfig struct {
	Username string
	Password string
	Role     string // "admin" or "operator"
}

type ServerConfig struct {
	Port          int    `yaml:"port,omitempty"`
	SessionSecret string `yaml:"session_secret,omitempty"`
	Timeout       int    `yaml:"timeout,omitempty"`
}

type HostConfig struct {
	ID                    string `yaml:"-"`
	Name                  string
	Host                  string
	Port                  int
	User                  string
	Password              string
	KeyPath               string
	KeyPassphrase         string
	InsecureIgnoreHostKey *bool
	KnownHostsPath        string
	PTY                   bool // Force pseudo-terminal shell mode (essential for Cisco IOS / switches)
	LegacyCiphers         bool // Enable legacy ciphers (DH group1/14, 3DES, AES-CBC, ssh-rsa)
}

type ButtonConfig struct {
	ID          string
	Label       string
	Description string
	Category    string
	Host        string
	Command     string
	Style       string // primary, danger, warning, success, secondary
	Confirm     bool
	Timeout     int // seconds
	PTY         bool
	Stdin       string // Optional input string to feed into session stdin (e.g. "y\n" or "\n")
}

type NormalizedCategory struct {
	Name        string
	Description string
	Buttons     []ButtonConfig
}

type AppConfig struct {
	Server          ServerConfig
	Users           []UserConfig
	UsersByUsername map[string]UserConfig
	Hosts           map[string]HostConfig
	ButtonsByID     map[string]ButtonConfig
	Categories      []NormalizedCategory
	LoadedAt        time.Time
	ConfigPath      string
}

type ConfigManager struct {
	mu     sync.RWMutex
	config *AppConfig
	path   string
}

func NewConfigManager(path string) (*ConfigManager, error) {
	cm := &ConfigManager{path: path}
	if err := cm.Reload(); err != nil {
		return nil, err
	}
	return cm, nil
}

// NewTestConfigManager returns a ConfigManager initialized with an in-memory AppConfig for testing.
func NewTestConfigManager(cfg *AppConfig) *ConfigManager {
	return &ConfigManager{config: cfg}
}

func (cm *ConfigManager) Get() *AppConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config
}

func (cm *ConfigManager) Reload() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cfg, err := loadConfigFromFile(cm.path)
	if err != nil {
		return err
	}
	cm.config = cfg
	return nil
}

func (cm *ConfigManager) ReadRawConfigFile() (string, error) {
	cm.mu.RLock()
	p := cm.path
	cm.mu.RUnlock()

	data, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (cm *ConfigManager) SaveConfigFile(content []byte) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// 1. In-memory validation
	var raw rawRoot
	if err := yaml.Unmarshal(content, &raw); err != nil {
		return fmt.Errorf("YAML validation error: %w", err)
	}

	// 2. Backup existing file
	if existingData, err := os.ReadFile(cm.path); err == nil {
		_ = os.WriteFile(cm.path+".bak", existingData, 0644)
	}

	// 3. Write directly to preserve Docker bind-mount inode
	f, err := os.OpenFile(cm.path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open config file for writing: %w", err)
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return fmt.Errorf("failed to write config content: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("failed to sync config file to disk: %w", err)
	}
	f.Close()

	// 4. Reload in memory
	cfg, err := loadConfigFromFile(cm.path)
	if err != nil {
		return fmt.Errorf("failed to reload updated config: %w", err)
	}
	cm.config = cfg
	return nil
}

// Internal raw unmarshaling types for clean YAML schema
type rawUser struct {
	User     string `yaml:"user"`
	Username string `yaml:"username"`
	Pass     string `yaml:"pass"`
	Password string `yaml:"password"`
	Role     string `yaml:"role"`
}

type rawHost struct {
	Name           string `yaml:"name"`
	Host           string `yaml:"host"`
	Address        string `yaml:"address"`
	Port           int    `yaml:"port"`
	User           string `yaml:"user"`
	Pass           string `yaml:"pass"`
	Password       string `yaml:"password"`
	Key            string `yaml:"key"`
	KeyPath        string `yaml:"key_path"`
	KeyPassphrase  string `yaml:"key_passphrase"`
	Insecure       *bool  `yaml:"insecure"`
	KnownHostsPath string `yaml:"known_hosts"`
	PTY            bool   `yaml:"pty"`
	LegacyCiphers  bool   `yaml:"legacy_ciphers"`
}

type rawButton struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Label       string `yaml:"label"`
	Cmd         string `yaml:"cmd"`
	Command     string `yaml:"command"`
	Host        string `yaml:"host"`
	Style       string `yaml:"style"`
	Confirm     bool   `yaml:"confirm"`
	Danger      bool   `yaml:"danger"`
	Warning     bool   `yaml:"warning"`
	Timeout     int    `yaml:"timeout"`
	Description string `yaml:"description"`
	PTY         *bool  `yaml:"pty"`
	Stdin       string `yaml:"stdin"`
	Input       string `yaml:"input"`
}

type rawCategory struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Host        string      `yaml:"host"`
	PTY         *bool       `yaml:"pty"`
	Buttons     []rawButton `yaml:"buttons"`
}

type rawRoot struct {
	Server     ServerConfig       `yaml:"server,omitempty"`
	Users      []rawUser          `yaml:"users"`
	Hosts      map[string]rawHost `yaml:"hosts"`
	Categories []rawCategory      `yaml:"categories"`
	Buttons    []rawButton        `yaml:"buttons"` // optional top-level buttons
}

func loadConfigFromFile(path string) (*AppConfig, error) {
	// Auto-initialize from config.example.yml if target config does not exist
	if _, err := os.Stat(path); os.IsNotExist(err) {
		examplePath := filepath.Join(filepath.Dir(path), "config.example.yml")
		if _, exErr := os.Stat(examplePath); os.IsNotExist(exErr) {
			examplePath = "config.example.yml"
		}
		if exData, readErr := os.ReadFile(examplePath); readErr == nil {
			if writeErr := os.WriteFile(path, exData, 0644); writeErr == nil {
				log.Printf("[INFO] %s not found; automatically initialized from %s", path, examplePath)
			}
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	var raw rawRoot
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse yaml config: %w", err)
	}

	// 1. Server settings: driven primarily by environment variables
	server := ServerConfig{
		Port:          8080,
		SessionSecret: "ssh-buttons-session-key-change-me",
		Timeout:       15,
	}

	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			server.Port = p
		}
	} else if raw.Server.Port > 0 {
		server.Port = raw.Server.Port
	}

	if envSecret := os.Getenv("SESSION_SECRET"); envSecret != "" {
		server.SessionSecret = envSecret
	} else if raw.Server.SessionSecret != "" {
		server.SessionSecret = raw.Server.SessionSecret
	}

	if envTimeout := os.Getenv("TIMEOUT"); envTimeout != "" {
		if t, err := strconv.Atoi(envTimeout); err == nil && t > 0 {
			server.Timeout = t
		}
	} else if envTimeout := os.Getenv("SSH_TIMEOUT"); envTimeout != "" {
		if t, err := strconv.Atoi(envTimeout); err == nil && t > 0 {
			server.Timeout = t
		}
	} else if raw.Server.Timeout > 0 {
		server.Timeout = raw.Server.Timeout
	}

	// 2. Process Users
	usersByUsername := make(map[string]UserConfig)
	var normalizedUsers []UserConfig

	for _, ru := range raw.Users {
		uname := ru.User
		if uname == "" {
			uname = ru.Username
		}
		uname = strings.TrimSpace(uname)
		if uname == "" {
			continue
		}

		pwd := ru.Pass
		if pwd == "" {
			pwd = ru.Password
		}

		role := ru.Role
		if role == "" {
			role = "admin"
		}

		u := UserConfig{
			Username: uname,
			Password: pwd,
			Role:     role,
		}
		usersByUsername[uname] = u
		normalizedUsers = append(normalizedUsers, u)
	}

	// Support env ADMIN_USER / ADMIN_PASSWORD override or fallback if no users defined
	envAdminUser := os.Getenv("ADMIN_USER")
	if envAdminUser == "" {
		envAdminUser = os.Getenv("ADMIN_USERNAME")
	}
	envAdminPass := os.Getenv("ADMIN_PASSWORD")
	if envAdminPass == "" {
		envAdminPass = os.Getenv("ADMIN_PASS")
	}

	if envAdminUser != "" && envAdminPass != "" {
		adminUser := UserConfig{
			Username: envAdminUser,
			Password: envAdminPass,
			Role:     "admin",
		}
		usersByUsername[envAdminUser] = adminUser
		normalizedUsers = append([]UserConfig{adminUser}, normalizedUsers...)
	} else if len(normalizedUsers) == 0 {
		// Default admin account if users block is completely empty
		defaultAdmin := UserConfig{
			Username: "admin",
			Password: "adminpassword",
			Role:     "admin",
		}
		usersByUsername["admin"] = defaultAdmin
		normalizedUsers = append(normalizedUsers, defaultAdmin)
	}

	// 3. Process Hosts
	normalizedHosts := make(map[string]HostConfig)
	for id, rh := range raw.Hosts {
		h := HostConfig{
			ID:   id,
			Name: rh.Name,
			Host: rh.Host,
			Port: rh.Port,
			User: rh.User,
		}
		if h.Name == "" {
			h.Name = id
		}
		if h.Host == "" {
			h.Host = rh.Address
		}
		if h.Port == 0 {
			h.Port = 22
		}

		h.Password = rh.Pass
		if h.Password == "" {
			h.Password = rh.Password
		}

		h.KeyPath = rh.Key
		if h.KeyPath == "" {
			h.KeyPath = rh.KeyPath
		}
		if h.KeyPath != "" && !filepath.IsAbs(h.KeyPath) {
			h.KeyPath = filepath.Clean(filepath.Join(filepath.Dir(path), h.KeyPath))
		}
		h.KeyPassphrase = rh.KeyPassphrase
		h.KnownHostsPath = rh.KnownHostsPath
		h.PTY = rh.PTY
		h.LegacyCiphers = rh.LegacyCiphers

		// Default insecure host key = true for easy homelab usage
		if rh.Insecure != nil {
			h.InsecureIgnoreHostKey = rh.Insecure
		} else {
			defaultInsecure := true
			h.InsecureIgnoreHostKey = &defaultInsecure
		}

		normalizedHosts[id] = h
	}

	// 4. Process Categories & Buttons
	buttonsByID := make(map[string]ButtonConfig)
	categoryMap := make(map[string][]ButtonConfig)
	var categoryOrder []string

	recordButton := func(catName, defaultHost string, catPTY *bool, rb rawButton) {
		label := rb.Name
		if label == "" {
			label = rb.Label
		}
		label = strings.TrimSpace(label)
		if label == "" {
			return
		}

		cmd := rb.Cmd
		if cmd == "" {
			cmd = rb.Command
		}

		targetHost := rb.Host
		if targetHost == "" {
			targetHost = defaultHost
		}

		style := rb.Style
		confirm := rb.Confirm

		// Resolve shorthand flags
		if rb.Danger {
			style = "danger"
			confirm = true
		} else if rb.Warning {
			style = "warning"
			confirm = true
		}
		if style == "" {
			style = "primary"
		}

		timeout := rb.Timeout
		if timeout <= 0 {
			timeout = server.Timeout
		}

		btnID := rb.ID
		if btnID == "" {
			btnID = slugify(catName + "_" + label)
		}

		// Resolve PTY mode: button override > category override > host setting > default false
		pty := false
		if rb.PTY != nil {
			pty = *rb.PTY
		} else if catPTY != nil {
			pty = *catPTY
		} else if h, ok := normalizedHosts[targetHost]; ok {
			pty = h.PTY
		}

		stdin := rb.Stdin
		if stdin == "" {
			stdin = rb.Input
		}

		btn := ButtonConfig{
			ID:          btnID,
			Label:       label,
			Description: rb.Description,
			Category:    catName,
			Host:        targetHost,
			Command:     cmd,
			Style:       style,
			Confirm:     confirm,
			Timeout:     timeout,
			PTY:         pty,
			Stdin:       stdin,
		}

		buttonsByID[btn.ID] = btn
		if _, exists := categoryMap[catName]; !exists {
			categoryOrder = append(categoryOrder, catName)
		}
		categoryMap[catName] = append(categoryMap[catName], btn)
	}

	categoryDescMap := make(map[string]string)

	// Process categories
	for _, cat := range raw.Categories {
		catName := cat.Name
		if catName == "" {
			catName = "General"
		}
		if cat.Description != "" {
			categoryDescMap[catName] = cat.Description
		}
		for _, btn := range cat.Buttons {
			recordButton(catName, cat.Host, cat.PTY, btn)
		}
	}

	// Process top-level buttons if any
	for _, btn := range raw.Buttons {
		recordButton("General", "", nil, btn)
	}

	var categories []NormalizedCategory
	for _, catName := range categoryOrder {
		categories = append(categories, NormalizedCategory{
			Name:        catName,
			Description: categoryDescMap[catName],
			Buttons:     categoryMap[catName],
		})
	}

	return &AppConfig{
		Server:          server,
		Users:           normalizedUsers,
		UsersByUsername: usersByUsername,
		Hosts:           normalizedHosts,
		ButtonsByID:     buttonsByID,
		Categories:      categories,
		LoadedAt:        time.Now(),
		ConfigPath:      path,
	}, nil
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if r == ' ' || r == '-' || r == '_' {
			b.WriteRune('-')
		}
	}
	res := strings.Trim(b.String(), "-")
	for strings.Contains(res, "--") {
		res = strings.ReplaceAll(res, "--", "-")
	}
	if res == "" {
		return fmt.Sprintf("btn-%d", time.Now().UnixNano()%100000)
	}
	return res
}
