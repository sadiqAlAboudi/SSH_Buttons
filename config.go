package main

import (
	"fmt"
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
	Port          int    `yaml:"port"`
	SessionSecret string `yaml:"session_secret"`
	Timeout       int    `yaml:"timeout"`
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
}

type NormalizedCategory struct {
	Name    string
	Buttons []ButtonConfig
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
		return fmt.Errorf("failed to sync config file: %w", err)
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
}

type rawCategory struct {
	Name    string      `yaml:"name"`
	Host    string      `yaml:"host"`
	Buttons []rawButton `yaml:"buttons"`
}

type rawRoot struct {
	Server     ServerConfig        `yaml:"server"`
	Users      []rawUser           `yaml:"users"`
	Hosts      map[string]rawHost  `yaml:"hosts"`
	Categories []rawCategory       `yaml:"categories"`
	Buttons    []rawButton         `yaml:"buttons"` // optional top-level buttons
}

func loadConfigFromFile(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	var raw rawRoot
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse yaml config: %w", err)
	}

	// 1. Server settings & defaults
	server := raw.Server
	if server.Port == 0 {
		server.Port = 8080
	}
	if server.SessionSecret == "" {
		server.SessionSecret = "ssh-buttons-session-key-change-me"
	}
	if server.Timeout <= 0 {
		server.Timeout = 15
	}

	// Environment variable overrides
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			server.Port = p
		}
	}
	if envSecret := os.Getenv("SESSION_SECRET"); envSecret != "" {
		server.SessionSecret = envSecret
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

	recordButton := func(catName, defaultHost string, rb rawButton) {
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
		}

		buttonsByID[btn.ID] = btn
		if _, exists := categoryMap[catName]; !exists {
			categoryOrder = append(categoryOrder, catName)
		}
		categoryMap[catName] = append(categoryMap[catName], btn)
	}

	// Process categories
	for _, cat := range raw.Categories {
		catName := cat.Name
		if catName == "" {
			catName = "General"
		}
		for _, btn := range cat.Buttons {
			recordButton(catName, cat.Host, btn)
		}
	}

	// Process top-level buttons if any
	for _, btn := range raw.Buttons {
		recordButton("General", "", btn)
	}

	var categories []NormalizedCategory
	for _, catName := range categoryOrder {
		categories = append(categories, NormalizedCategory{
			Name:    catName,
			Buttons: categoryMap[catName],
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
