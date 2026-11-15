package config

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

	// config.yml does not exist yet!
	cm, err := NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to auto-init config: %v", err)
	}

	// Verify config.yml was created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatal("Expected config.yml to be automatically created with default starter configuration")
	}

	cfg := cm.Get()
	if _, ok := cfg.UsersByUsername["admin"]; !ok {
		t.Errorf("Expected admin user loaded from auto-generated config, got %+v", cfg.UsersByUsername)
	}
	if len(cfg.Hosts) != 0 {
		t.Errorf("Expected 0 sample hosts in clean starter config, got %d hosts", len(cfg.Hosts))
	}
	if len(cfg.Categories) != 0 {
		t.Errorf("Expected 0 sample categories in clean starter config, got %d categories", len(cfg.Categories))
	}
}

func TestConfigAutoInitialization_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")

	// Create a 0-byte file (simulating touch config.yml)
	if err := os.WriteFile(configPath, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create empty file: %v", err)
	}

	cm, err := NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to auto-init config from empty file: %v", err)
	}

	// Check that file was populated
	data, err := os.ReadFile(configPath)
	if err != nil || len(data) == 0 {
		t.Fatalf("Expected config.yml to be populated with starter configuration, got length %d", len(data))
	}

	cfg := cm.Get()
	if _, ok := cfg.UsersByUsername["admin"]; !ok {
		t.Errorf("Expected admin user loaded from empty-file populated config, got %+v", cfg.UsersByUsername)
	}
}

func TestConfigAutoInitialization_Directory(t *testing.T) {
	tmpDir := t.TempDir()
	// Simulating Docker bind mount creating a directory named config.yml
	dirPath := filepath.Join(tmpDir, "config.yml")
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	cm, err := NewConfigManager(dirPath)
	if err != nil {
		t.Fatalf("Failed to auto-init config from directory: %v", err)
	}

	// Candidate file should be created inside the directory
	expectedFile := filepath.Join(dirPath, "config.yml")
	if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
		t.Fatalf("Expected %s to be created inside directory", expectedFile)
	}

	cfg := cm.Get()
	if _, ok := cfg.UsersByUsername["admin"]; !ok {
		t.Errorf("Expected admin user loaded, got %+v", cfg.UsersByUsername)
	}

	// Verify saving works through the resolved path
	raw, err := cm.GetRawConfig()
	if err != nil {
		t.Fatalf("Failed to get raw config: %v", err)
	}
	raw.Server.Port = 9090
	if err := cm.SaveStructuredConfig(raw); err != nil {
		t.Fatalf("Failed to save structured config to directory-resolved path: %v", err)
	}

	reloadedCfg := cm.Get()
	if reloadedCfg.Server.Port != 9090 {
		t.Errorf("Expected port 9090 after save, got %d", reloadedCfg.Server.Port)
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

func TestConfigPTYAndNetworkDeviceFields(t *testing.T) {
	yamlContent := `
hosts:
  cisco_core:
    name: "Cisco Catalyst 3750"
    host: "10.1.1.1"
    user: "admin"
    pass: "ciscopass"
    pty: true
    legacy_ciphers: true

  mikrotik_gw:
    name: "MikroTik Gateway"
    host: "10.1.1.254"
    user: "admin"
    pass: "mtpass"

categories:
  - name: "Network Switches"
    host: "cisco_core"
    buttons:
      - name: "Show Interfaces"
        cmd: "show ip int brief"
      - name: "Direct Exec"
        cmd: "show clock"
        pty: false

  - name: "MikroTik Ops"
    host: "mikrotik_gw"
    buttons:
      - name: "Reboot Router"
        cmd: "/system reboot"
        stdin: "y\n"
        danger: true
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

	// Verify Host fields
	cisco, ok := cfg.Hosts["cisco_core"]
	if !ok {
		t.Fatalf("Host cisco_core not found")
	}
	if !cisco.PTY {
		t.Errorf("Expected cisco_core to have PTY=true")
	}
	if !cisco.LegacyCiphers {
		t.Errorf("Expected cisco_core to have LegacyCiphers=true")
	}

	// Verify Button inherited PTY
	btnShow, ok := cfg.ButtonsByID["network-switches-show-interfaces"]
	if !ok {
		t.Fatalf("Button network-switches-show-interfaces not found")
	}
	if !btnShow.PTY {
		t.Errorf("Expected button to inherit PTY=true from host, got false")
	}

	// Verify Button explicit PTY override to false
	btnClock, ok := cfg.ButtonsByID["network-switches-direct-exec"]
	if !ok {
		t.Fatalf("Button network-switches-direct-exec not found")
	}
	if btnClock.PTY {
		t.Errorf("Expected button explicit override PTY=false, got true")
	}

	// Verify MikroTik Stdin
	btnReboot, ok := cfg.ButtonsByID["mikrotik-ops-reboot-router"]
	if !ok {
		t.Fatalf("Button mikrotik-ops-reboot-router not found")
	}
	if btnReboot.Stdin != "y\n" {
		t.Errorf("Expected stdin 'y\\n', got %q", btnReboot.Stdin)
	}
}

func TestSaveStructuredConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	initialYAML := `
users:
  - user: "admin"
    pass: "adminpass"
    role: "admin"
hosts:
  host1:
    name: "Server 1"
    host: "10.0.0.1"
    user: "root"
categories:
  - name: "General"
    buttons:
      - name: "Status"
        cmd: "uptime"
`
	if err := os.WriteFile(configPath, []byte(initialYAML), 0644); err != nil {
		t.Fatalf("Failed to write initial config: %v", err)
	}

	cm, err := NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to create ConfigManager: %v", err)
	}

	raw, err := cm.GetRawConfig()
	if err != nil {
		t.Fatalf("GetRawConfig failed: %v", err)
	}

	if len(raw.Users) != 1 || raw.Users[0].User != "admin" {
		t.Fatalf("Unexpected users in raw config: %+v", raw.Users)
	}

	// 1. Test auto-injection of default admin when saving without admin user
	noAdminRaw := raw
	noAdminRaw.Users = []RawUser{
		{User: "operator1", Pass: "somepass", Role: "operator"},
	}
	if err := cm.SaveStructuredConfig(noAdminRaw); err != nil {
		t.Fatalf("Expected SaveStructuredConfig to auto-inject default admin, got error: %v", err)
	}
	if _, ok := cm.Get().UsersByUsername["admin"]; !ok {
		t.Errorf("Expected auto-injected admin in config")
	}

	// 2. Add an operator user with plaintext password and save
	raw.Users = append(raw.Users, RawUser{
		User: "operator1",
		Pass: "newSecret123",
		Role: "operator",
	})
	// Add a new host and button
	if raw.Hosts == nil {
		raw.Hosts = make(map[string]RawHost)
	}
	raw.Hosts["host2"] = RawHost{
		Name: "Server 2",
		Host: "10.0.0.2",
		User: "admin",
		Pass: "hostpass",
	}
	raw.Categories[0].Buttons = append(raw.Categories[0].Buttons, RawButton{
		Name:  "Disk Check",
		Cmd:   "df -h",
		Host:  "host2",
		Style: "primary",
	})

	if err := cm.SaveStructuredConfig(raw); err != nil {
		t.Fatalf("SaveStructuredConfig failed: %v", err)
	}

	// Verify reload
	cfg := cm.Get()
	if len(cfg.Users) != 2 {
		t.Errorf("Expected 2 users after save, got %d", len(cfg.Users))
	}
	opUser, ok := cfg.UsersByUsername["operator1"]
	if !ok {
		t.Fatalf("Expected operator1 to exist in loaded users")
	}
	// Verify password was hashed with bcrypt
	if !strings.HasPrefix(opUser.Password, "$2a$") {
		t.Errorf("Expected operator1 password to be hashed with bcrypt, got %q", opUser.Password)
	}
	// Verify new host and button
	if _, ok := cfg.Hosts["host2"]; !ok {
		t.Errorf("Expected host2 in config hosts")
	}
	if len(cfg.Categories[0].Buttons) != 2 {
		t.Errorf("Expected 2 buttons in category, got %d", len(cfg.Categories[0].Buttons))
	}
}

