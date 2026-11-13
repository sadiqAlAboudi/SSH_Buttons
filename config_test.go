package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigCleanSchemaAndDefaults(t *testing.T) {
	// Notice: NO server: block in YAML! Server is configured via environment.
	yamlContent := `
users:
  - user: "testadmin"
    pass: "testpassword"
    role: "admin"

hosts:
  h1:
    name: "Test Host 1"
    host: "10.0.0.1"
    user: "testuser"
    pass: "pwd"

categories:
  - name: "Maintenance"
    host: "h1"
    buttons:
      - name: "Check Uptime"
        cmd: "uptime"
        style: "success"
      - name: "Hard Reboot"
        cmd: "sudo reboot"
        danger: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write temp config: %v", err)
	}

	t.Setenv("PORT", "9090")
	t.Setenv("TIMEOUT", "25")

	cm, err := NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	cfg := cm.Get()
	if cfg.Server.Port != 9090 {
		t.Errorf("Expected port 9090 from env, got %d", cfg.Server.Port)
	}
	if cfg.Server.Timeout != 25 {
		t.Errorf("Expected timeout 25 from env, got %d", cfg.Server.Timeout)
	}

	// Verify User
	user, ok := cfg.UsersByUsername["testadmin"]
	if !ok || user.Password != "testpassword" || user.Role != "admin" {
		t.Errorf("User testadmin missing or invalid: %v", user)
	}

	// Verify Host and Port default 22
	h1, ok := cfg.Hosts["h1"]
	if !ok || h1.Port != 22 {
		t.Errorf("Host h1 port mismatch, expected default 22, got %v", h1)
	}

	// Verify Button 1 with inherited host and auto-generated slug
	btnUptime, ok := cfg.ButtonsByID["maintenance-check-uptime"]
	if !ok {
		t.Fatalf("Expected auto-generated ID 'maintenance-check-uptime', available IDs: %+v", cfg.ButtonsByID)
	}
	if btnUptime.Host != "h1" {
		t.Errorf("Expected inherited host 'h1', got %s", btnUptime.Host)
	}
	if btnUptime.Command != "uptime" {
		t.Errorf("Expected command 'uptime', got %s", btnUptime.Command)
	}
	if btnUptime.Timeout != 25 {
		t.Errorf("Expected default timeout 25, got %d", btnUptime.Timeout)
	}

	// Verify Button 2 with danger shorthand
	btnReboot, ok := cfg.ButtonsByID["maintenance-hard-reboot"]
	if !ok {
		t.Fatalf("Expected auto-generated ID 'maintenance-hard-reboot', available: %+v", cfg.ButtonsByID)
	}
	if btnReboot.Style != "danger" || !btnReboot.Confirm {
		t.Errorf("Expected danger shorthand to set style=danger and confirm=true, got style=%s, confirm=%v", btnReboot.Style, btnReboot.Confirm)
	}
}

func TestConfigAutoInitialization(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	examplePath := filepath.Join(tmpDir, "config.example.yml")

	exampleContent := `
users:
  - user: "auto_admin"
    pass: "autopass"
`
	if err := os.WriteFile(examplePath, []byte(exampleContent), 0644); err != nil {
		t.Fatalf("Failed to create example file: %v", err)
	}

	// config.yml does not exist yet!
	cm, err := NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to auto-init config: %v", err)
	}

	// Verify config.yml was created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatal("Expected config.yml to be automatically created from config.example.yml")
	}

	cfg := cm.Get()
	if _, ok := cfg.UsersByUsername["auto_admin"]; !ok {
		t.Errorf("Expected auto_admin user loaded from auto-copied config, got %+v", cfg.UsersByUsername)
	}
}

func TestConfigMultiUsers(t *testing.T) {
	yamlContent := `
users:
  - user: "chief"
    pass: "chiefpassword"
    role: "admin"
  - user: "operator_sam"
    pass: "sampassword"
    role: "operator"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write temp config: %v", err)
	}

	cm, err := NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	cfg := cm.Get()
	chief, ok := cfg.UsersByUsername["chief"]
	if !ok || chief.Role != "admin" {
		t.Errorf("Expected chief with admin role, got %v", chief)
	}

	sam, ok := cfg.UsersByUsername["operator_sam"]
	if !ok || sam.Role != "operator" {
		t.Errorf("Expected sam with operator role, got %v", sam)
	}
}

func TestConfigSaveAndValidate(t *testing.T) {
	yamlContent := `
users:
  - user: "admin"
    pass: "adminpassword"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write temp config: %v", err)
	}

	cm, err := NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// 1. Invalid YAML should fail and not alter file
	invalidYAML := `
users: [unclosed bracket
`
	err = cm.SaveConfigFile([]byte(invalidYAML))
	if err == nil {
		t.Fatal("Expected error when saving invalid YAML, got nil")
	}

	raw, _ := cm.ReadRawConfigFile()
	if strings.Contains(raw, "unclosed bracket") {
		t.Fatal("Invalid YAML was saved to disk despite error")
	}

	// 2. Valid YAML should save, backup, and reload
	validYAML := `
users:
  - user: "superadmin"
    pass: "superpassword"
`
	err = cm.SaveConfigFile([]byte(validYAML))
	if err != nil {
		t.Fatalf("Failed to save valid YAML: %v", err)
	}

	// Check backup file exists
	if _, err := os.Stat(configPath + ".bak"); err != nil {
		t.Errorf("Expected backup file %s.bak to exist: %v", configPath, err)
	}

	// Check memory was reloaded
	cfg := cm.Get()
	super, ok := cfg.UsersByUsername["superadmin"]
	if !ok || super.Password != "superpassword" {
		t.Errorf("Expected reloaded user superadmin, got %v", super)
	}
}
