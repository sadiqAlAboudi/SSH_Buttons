package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Port              int    `yaml:"port"`
	AdminUsername     string `yaml:"admin_username"`
	AdminPassword     string `yaml:"admin_password"`
	SessionSecret     string `yaml:"session_secret"`
	DefaultSSHTimeout int    `yaml:"default_ssh_timeout"`
}

type HostConfig struct {
	ID                    string `yaml:"id,omitempty"` // populated if hosts is list or map
	Name                  string `yaml:"name"`
	Host                  string `yaml:"host"`
	Port                  int    `yaml:"port"`
	User                  string `yaml:"user"`
	Password              string `yaml:"password"`
	KeyPath               string `yaml:"key_path"`
	KeyPassphrase         string `yaml:"key_passphrase"`
	InsecureIgnoreHostKey *bool  `yaml:"insecure_ignore_host_key"`
	KnownHostsPath        string `yaml:"known_hosts_path"`
}

type ButtonConfig struct {
	ID          string `yaml:"id"`
	Label       string `yaml:"label"`
	Description string `yaml:"description"`
	Category    string `yaml:"category"`
	Host        string `yaml:"host"`
	Command     string `yaml:"command"`
	Style       string `yaml:"style"` // primary, danger, warning, success, secondary
	Confirm     bool   `yaml:"confirm"`
	Timeout     int    `yaml:"timeout"` // in seconds
}

type CategoryConfig struct {
	Name    string         `yaml:"name"`
	Buttons []ButtonConfig `yaml:"buttons"`
}

type RawConfig struct {
	Server     ServerConfig          `yaml:"server"`
	Hosts      map[string]HostConfig `yaml:"hosts"`
	Buttons    []ButtonConfig        `yaml:"buttons"`
	Categories []CategoryConfig      `yaml:"categories"`
}

type NormalizedCategory struct {
	Name    string
	Buttons []ButtonConfig
}

type AppConfig struct {
	Server        ServerConfig
	Hosts         map[string]HostConfig
	ButtonsByID   map[string]ButtonConfig
	Categories    []NormalizedCategory
	LoadedAt      time.Time
	ConfigPath    string
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

func loadConfigFromFile(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	var raw RawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse yaml config: %w", err)
	}

	// Apply default server settings
	if raw.Server.Port == 0 {
		raw.Server.Port = 8080
	}
	if raw.Server.AdminUsername == "" {
		raw.Server.AdminUsername = "admin"
	}
	if raw.Server.AdminPassword == "" {
		raw.Server.AdminPassword = "admin"
	}
	if raw.Server.SessionSecret == "" {
		raw.Server.SessionSecret = "ssh-buttons-session-key-change-me"
	}
	if raw.Server.DefaultSSHTimeout <= 0 {
		raw.Server.DefaultSSHTimeout = 15
	}

	// Environment variable overrides
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			raw.Server.Port = p
		}
	}
	if envUser := os.Getenv("ADMIN_USER"); envUser != "" {
		raw.Server.AdminUsername = envUser
	} else if envUser := os.Getenv("ADMIN_USERNAME"); envUser != "" {
		raw.Server.AdminUsername = envUser
	}
	if envPass := os.Getenv("ADMIN_PASSWORD"); envPass != "" {
		raw.Server.AdminPassword = envPass
	} else if envPass := os.Getenv("ADMIN_PASS"); envPass != "" {
		raw.Server.AdminPassword = envPass
	}
	if envSecret := os.Getenv("SESSION_SECRET"); envSecret != "" {
		raw.Server.SessionSecret = envSecret
	}

	// Process Hosts
	normalizedHosts := make(map[string]HostConfig)
	for id, h := range raw.Hosts {
		h.ID = id
		if h.Port == 0 {
			h.Port = 22
		}
		if h.Name == "" {
			h.Name = id
		}
		// Resolve relative key path against config file directory
		if h.KeyPath != "" && !filepath.IsAbs(h.KeyPath) {
			h.KeyPath = filepath.Clean(filepath.Join(filepath.Dir(path), h.KeyPath))
		}
		// Default to insecure ignore host key = true for easy homelab usage if not specified
		if h.InsecureIgnoreHostKey == nil {
			defaultInsecure := true
			h.InsecureIgnoreHostKey = &defaultInsecure
		}
		normalizedHosts[id] = h
	}

	// Process Buttons & Categories
	buttonsByID := make(map[string]ButtonConfig)
	categoryMap := make(map[string][]ButtonConfig)
	var categoryOrder []string

	recordButton := func(catName string, btn ButtonConfig) {
		if btn.ID == "" {
			return
		}
		if btn.Style == "" {
			btn.Style = "primary"
		}
		if btn.Timeout <= 0 {
			btn.Timeout = raw.Server.DefaultSSHTimeout
		}
		btn.Category = catName
		buttonsByID[btn.ID] = btn

		if _, exists := categoryMap[catName]; !exists {
			categoryOrder = append(categoryOrder, catName)
		}
		categoryMap[catName] = append(categoryMap[catName], btn)
	}

	// 1. Process from raw.Categories
	for _, cat := range raw.Categories {
		catName := cat.Name
		if catName == "" {
			catName = "General"
		}
		for _, btn := range cat.Buttons {
			recordButton(catName, btn)
		}
	}

	// 2. Process from raw.Buttons
	for _, btn := range raw.Buttons {
		catName := btn.Category
		if catName == "" {
			catName = "General"
		}
		recordButton(catName, btn)
	}

	var categories []NormalizedCategory
	for _, catName := range categoryOrder {
		categories = append(categories, NormalizedCategory{
			Name:    catName,
			Buttons: categoryMap[catName],
		})
	}

	return &AppConfig{
		Server:      raw.Server,
		Hosts:       normalizedHosts,
		ButtonsByID: buttonsByID,
		Categories:  categories,
		LoadedAt:    time.Now(),
		ConfigPath:  path,
	}, nil
}
