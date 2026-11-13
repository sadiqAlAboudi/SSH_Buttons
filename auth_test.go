package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestAuthCredentialsAndTokens(t *testing.T) {
	// Generate a bcrypt password
	hashed, err := bcrypt.GenerateFromPassword([]byte("secretbcrypt"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate bcrypt: %v", err)
	}

	yamlContent := `
server:
  admin_username: "sysadmin"
  admin_password: "` + string(hashed) + `"
  session_secret: "super-secret-signing-key"
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

	auth := NewAuthService(cm)

	// Test valid credentials
	if !auth.CheckCredentials("sysadmin", "secretbcrypt") {
		t.Errorf("CheckCredentials failed with valid bcrypt password")
	}

	// Test invalid credentials
	if auth.CheckCredentials("sysadmin", "wrongpassword") {
		t.Errorf("CheckCredentials succeeded with wrong password")
	}
	if auth.CheckCredentials("wronguser", "secretbcrypt") {
		t.Errorf("CheckCredentials succeeded with wrong username")
	}

	// Test token generation & validation
	token := auth.GenerateSessionToken("sysadmin")
	user, valid := auth.ValidateSessionToken(token)
	if !valid || user != "sysadmin" {
		t.Errorf("ValidateSessionToken failed for freshly generated token: got %s, %v", user, valid)
	}

	// Test tampered token
	tampered := token + "tampered"
	if _, valid := auth.ValidateSessionToken(tampered); valid {
		t.Errorf("ValidateSessionToken accepted tampered token")
	}
}
