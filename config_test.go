package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigLoadAndDefaults(t *testing.T) {
	yamlContent := `
server:
  port: 9090
  admin_username: "testadmin"
  admin_password: "testpassword"

hosts:
  h1:
    name: "Test Host 1"
    host: "10.0.0.1"
    port: 2222
    user: "testuser"
    password: "pwd"

categories:
  - name: "Maintenance"
    buttons:
      - id: "btn-uptime"
        label: "Check Uptime"
        host: "h1"
        command: "uptime"
        style: "success"
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
	if cfg.Server.Port != 9090 {
		t.Errorf("Expected port 9090, got %d", cfg.Server.Port)
	}
	if cfg.Server.AdminUsername != "testadmin" {
		t.Errorf("Expected admin_username testadmin, got %s", cfg.Server.AdminUsername)
	}
	if len(cfg.Hosts) != 1 {
		t.Errorf("Expected 1 host, got %d", len(cfg.Hosts))
	}
	h1, ok := cfg.Hosts["h1"]
	if !ok || h1.Port != 2222 {
		t.Errorf("Host h1 port mismatch, expected 2222, got %v", h1)
	}
	btn, ok := cfg.ButtonsByID["btn-uptime"]
	if !ok || btn.Label != "Check Uptime" {
		t.Errorf("Button btn-uptime missing or invalid: %v", btn)
	}
	if btn.Timeout != 15 { // default applied
		t.Errorf("Expected default timeout 15, got %d", btn.Timeout)
	}
}

func TestConfigEnvOverrides(t *testing.T) {
	yamlContent := `
server:
  port: 8080
  admin_username: "original"
  admin_password: "old"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write temp config: %v", err)
	}

	t.Setenv("PORT", "7777")
	t.Setenv("ADMIN_USER", "envadmin")
	t.Setenv("ADMIN_PASSWORD", "newsecret")

	cm, err := NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	cfg := cm.Get()
	if cfg.Server.Port != 7777 {
		t.Errorf("Expected port 7777 from env, got %d", cfg.Server.Port)
	}
	if cfg.Server.AdminUsername != "envadmin" {
		t.Errorf("Expected user envadmin from env, got %s", cfg.Server.AdminUsername)
	}
	if cfg.Server.AdminPassword != "newsecret" {
		t.Errorf("Expected password newsecret from env, got %s", cfg.Server.AdminPassword)
	}
}
