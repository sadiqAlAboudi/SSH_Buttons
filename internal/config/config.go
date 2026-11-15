package config

import (
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
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
	resolvedPath, err := resolveConfigPath(path)
	if err != nil {
		return nil, err
	}
	cm := &ConfigManager{path: resolvedPath}
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

	resolvedPath, err := resolveConfigPath(cm.path)
	if err != nil {
		return err
	}
	cm.path = resolvedPath

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

// GetRawConfig parses the configuration file into RawRoot for structured editing.
func (cm *ConfigManager) GetRawConfig() (RawRoot, error) {
	cm.mu.RLock()
	filePath := cm.path
	cm.mu.RUnlock()

	var raw RawRoot
	if filePath == "" {
		return raw, errors.New("no config file path defined")
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return raw, fmt.Errorf("failed to read config file %q: %w", filePath, err)
	}

	if err := yaml.Unmarshal(data, &raw); err != nil {
		return raw, fmt.Errorf("failed to parse yaml config: %w", err)
	}
	return raw, nil
}

// SaveStructuredConfig validates and serializes a RawRoot struct to YAML, hashes any plaintext passwords, and persists it.
func (cm *ConfigManager) SaveStructuredConfig(raw RawRoot) error {
	// 1. Validate users. If no admin account is provided, automatically inject the default admin user.
	hasAdmin := false
	for _, u := range raw.Users {
		uname := u.User
		if uname == "" {
			uname = u.Username
		}
		if uname == "" {
			return errors.New("every user must have a username")
		}
		if u.Role == "admin" {
			hasAdmin = true
		}
	}
	if !hasAdmin {
		adminUser := "admin"
		if u := os.Getenv("ADMIN_USER"); u != "" {
			adminUser = u
		} else if u := os.Getenv("ADMIN_USERNAME"); u != "" {
			adminUser = u
		}
		adminPass := "adminpassword"
		if p := os.Getenv("ADMIN_PASSWORD"); p != "" {
			adminPass = p
		} else if p := os.Getenv("ADMIN_PASS"); p != "" {
			adminPass = p
		}
		raw.Users = append([]RawUser{{
			User: adminUser,
			Pass: adminPass,
			Role: "admin",
		}}, raw.Users...)
	}

	// 2. Hash any new plaintext passwords with bcrypt
	for i := range raw.Users {
		pass := raw.Users[i].Pass
		if pass == "" {
			pass = raw.Users[i].Password
		}
		if pass != "" && !strings.HasPrefix(pass, "$2a$") && !strings.HasPrefix(pass, "$2b$") && !strings.HasPrefix(pass, "$2y$") {
			hashed, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("failed to hash password for user %q: %w", raw.Users[i].User, err)
			}
			raw.Users[i].Pass = string(hashed)
			raw.Users[i].Password = ""
		}
	}

	// 3. Serialize cleanly to YAML
	out, err := yaml.Marshal(&raw)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %w", err)
	}

	return cm.SaveConfigFile(out)
}

func (cm *ConfigManager) SaveConfigFile(content []byte) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// 1. In-memory validation
	var raw RawRoot
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

// Raw unmarshaling and serialization types for GUI and YAML schema
type RawUser struct {
	User     string `yaml:"user" json:"user"`
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Pass     string `yaml:"pass" json:"pass"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
	Role     string `yaml:"role" json:"role"`
}

type RawHost struct {
	Name           string `yaml:"name" json:"name"`
	Host           string `yaml:"host" json:"host"`
	Address        string `yaml:"address,omitempty" json:"address,omitempty"`
	Port           int    `yaml:"port,omitempty" json:"port,omitempty"`
	User           string `yaml:"user" json:"user"`
	Pass           string `yaml:"pass,omitempty" json:"pass,omitempty"`
	Password       string `yaml:"password,omitempty" json:"password,omitempty"`
	Key            string `yaml:"key,omitempty" json:"key,omitempty"`
	KeyPath        string `yaml:"key_path,omitempty" json:"key_path,omitempty"`
	KeyPassphrase  string `yaml:"key_passphrase,omitempty" json:"key_passphrase,omitempty"`
	Insecure       *bool  `yaml:"insecure,omitempty" json:"insecure,omitempty"`
	KnownHostsPath string `yaml:"known_hosts,omitempty" json:"known_hosts,omitempty"`
	PTY            bool   `yaml:"pty,omitempty" json:"pty,omitempty"`
	LegacyCiphers  bool   `yaml:"legacy_ciphers,omitempty" json:"legacy_ciphers,omitempty"`
}

type RawButton struct {
	ID          string `yaml:"id,omitempty" json:"id,omitempty"`
	Name        string `yaml:"name" json:"name"`
	Label       string `yaml:"label,omitempty" json:"label,omitempty"`
	Cmd         string `yaml:"cmd" json:"cmd"`
	Command     string `yaml:"command,omitempty" json:"command,omitempty"`
	Host        string `yaml:"host,omitempty" json:"host,omitempty"`
	Style       string `yaml:"style,omitempty" json:"style,omitempty"`
	Confirm     bool   `yaml:"confirm,omitempty" json:"confirm,omitempty"`
	Danger      bool   `yaml:"danger,omitempty" json:"danger,omitempty"`
	Warning     bool   `yaml:"warning,omitempty" json:"warning,omitempty"`
	Timeout     int    `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	PTY         *bool  `yaml:"pty,omitempty" json:"pty,omitempty"`
	Stdin       string `yaml:"stdin,omitempty" json:"stdin,omitempty"`
	Input       string `yaml:"input,omitempty" json:"input,omitempty"`
}

type RawCategory struct {
	Name        string      `yaml:"name" json:"name"`
	Description string      `yaml:"description,omitempty" json:"description,omitempty"`
	Host        string      `yaml:"host,omitempty" json:"host,omitempty"`
	PTY         *bool       `yaml:"pty,omitempty" json:"pty,omitempty"`
	Buttons     []RawButton `yaml:"buttons" json:"buttons"`
}

type RawRoot struct {
	Server     ServerConfig       `yaml:"server,omitempty" json:"server,omitempty"`
	Users      []RawUser          `yaml:"users" json:"users"`
	Hosts      map[string]RawHost `yaml:"hosts" json:"hosts"`
	Categories []RawCategory      `yaml:"categories" json:"categories"`
	Buttons    []RawButton        `yaml:"buttons,omitempty" json:"buttons,omitempty"`
}

// DefaultConfigYAML is the built-in clean starter configuration with only the default admin user.
const DefaultConfigYAML = `# ==============================================================================
# SSH Buttons - Configuration (config.yml)
# Full documentation & configuration reference: visit /docs in the Web UI
# ==============================================================================

# 1. User Accounts & Roles (roles: "admin" | "operator")
users:
  - user: "admin"
    pass: "adminpassword"
    role: "admin"

# 2. Target Remote Hosts (Add your hosts in the GUI Config Editor or define below)
hosts: {}

# 3. Categories & Action Buttons (Add your buttons in the GUI Config Editor or define below)
categories: []
`

// GenerateDefaultConfigYAML creates a starter configuration with the default user and environment overrides.
func GenerateDefaultConfigYAML() string {
	adminUser := "admin"
	if u := os.Getenv("ADMIN_USER"); u != "" {
		adminUser = u
	} else if u := os.Getenv("ADMIN_USERNAME"); u != "" {
		adminUser = u
	}

	adminPass := "adminpassword"
	if p := os.Getenv("ADMIN_PASSWORD"); p != "" {
		adminPass = p
	} else if p := os.Getenv("ADMIN_PASS"); p != "" {
		adminPass = p
	}

	return fmt.Sprintf(`# ==============================================================================
# SSH Buttons - Configuration (config.yml)
# Full documentation & configuration reference: visit /docs in the Web UI
# ==============================================================================

# 1. User Accounts & Roles (roles: "admin" | "operator")
users:
  - user: %q
    pass: %q
    role: "admin"

# 2. Target Remote Hosts (Add your hosts in the GUI Config Editor or define below)
hosts: {}

# 3. Categories & Action Buttons (Add your buttons in the GUI Config Editor or define below)
categories: []
`, adminUser, adminPass)
}

// resolveConfigPath checks if the path exists, is empty, or is a directory (e.g. from a Docker volume bind mount),
// automatically initializing the starter configuration and returning the concrete file path.
func resolveConfigPath(path string) (string, error) {
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0755)
		}
		defaultContent := GenerateDefaultConfigYAML()
		if writeErr := os.WriteFile(path, []byte(defaultContent), 0644); writeErr != nil {
			return "", fmt.Errorf("failed to initialize default config at %q: %w", path, writeErr)
		}
		log.Printf("[INFO] %s not found; automatically initialized with default starter configuration", path)
		return path, nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to inspect config path %q: %w", path, err)
	}

	if fi.IsDir() {
		// Target path is a directory (e.g., Docker created a directory for a missing bind mount)
		candidate := filepath.Join(path, "config.yml")
		candFi, candErr := os.Stat(candidate)
		if os.IsNotExist(candErr) {
			defaultContent := GenerateDefaultConfigYAML()
			if writeErr := os.WriteFile(candidate, []byte(defaultContent), 0644); writeErr != nil {
				return "", fmt.Errorf("config path %q is a directory, and failed to create %q inside it: %w. "+
					"This happens when Docker mounts a file before it exists on the host. "+
					"Please stop the container ('docker compose down'), delete the %q directory on your host, "+
					"create %q as a file, and restart",
					path, candidate, writeErr, filepath.Base(path), filepath.Base(path))
			}
			log.Printf("[INFO] Config path %q is a directory; automatically initialized starter config at %q", path, candidate)
			return candidate, nil
		}
		if candErr != nil {
			return "", fmt.Errorf("failed to inspect candidate config file %q: %w", candidate, candErr)
		}
		if candFi.IsDir() {
			return "", fmt.Errorf("config path %q and inner candidate %q are both directories", path, candidate)
		}
		log.Printf("[INFO] Config path %q is a directory; using config file at %q", path, candidate)
		return candidate, nil
	}

	// Target is a file: if empty (0 bytes), populate it with default starter config
	if fi.Size() == 0 {
		defaultContent := GenerateDefaultConfigYAML()
		if writeErr := os.WriteFile(path, []byte(defaultContent), 0644); writeErr == nil {
			log.Printf("[INFO] Config file %q is empty; automatically populated with default starter configuration", path)
		} else {
			log.Printf("[WARN] Failed to populate empty config file %q: %v", path, writeErr)
		}
	}

	return path, nil
}

func loadConfigFromFile(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		defaultContent := GenerateDefaultConfigYAML()
		_ = os.WriteFile(path, []byte(defaultContent), 0644)
		data = []byte(defaultContent)
	}

	var raw RawRoot
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

	recordButton := func(catName, defaultHost string, catPTY *bool, rb RawButton) {
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
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || unicode.IsLetter(r) || unicode.IsDigit(r) {
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
		h := fnv.New32a()
		h.Write([]byte(s))
		return fmt.Sprintf("btn-%08x", h.Sum32())
	}
	return res
}
