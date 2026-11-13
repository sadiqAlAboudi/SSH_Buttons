package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"ssh_buttons/internal/config"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestGracefulDisconnect(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		cmd      string
		expected bool
	}{
		{
			name:     "Nil error",
			err:      nil,
			cmd:      "sudo reboot",
			expected: false,
		},
		{
			name:     "Reboot with io.EOF",
			err:      io.EOF,
			cmd:      "sudo reboot",
			expected: true,
		},
		{
			name:     "Shutdown with connection reset",
			err:      errors.New("read tcp 192.168.1.5:45212->192.168.1.10:22: read: connection reset by peer"),
			cmd:      "sudo shutdown -h now",
			expected: true,
		},
		{
			name:     "MikroTik reboot with closed by remote host",
			err:      errors.New("ssh: connection closed by remote host"),
			cmd:      "/system reboot",
			expected: true,
		},
		{
			name:     "Broken pipe during reboot",
			err:      errors.New("write: broken pipe"),
			cmd:      "reboot",
			expected: true,
		},
		{
			name:     "Cisco reload with connection reset",
			err:      errors.New("read tcp 192.168.1.2:50123->192.168.1.1:22: connection reset by peer"),
			cmd:      "reload",
			expected: true,
		},
		{
			name:     "Cisco reload with EOF",
			err:      io.EOF,
			cmd:      "reload",
			expected: true,
		},
		{
			name:     "Normal command with connection failure",
			err:      io.EOF,
			cmd:      "df -h",
			expected: false, // Not a reboot command, should report as failure
		},
		{
			name:     "Reboot with permission error",
			err:      errors.New("exit status 1: sudo: password required"),
			cmd:      "sudo reboot",
			expected: false, // Real exit status 1 failure
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := isGracefulDisconnect(tc.err, tc.cmd)
			if res != tc.expected {
				t.Errorf("isGracefulDisconnect() for %s: got %v, want %v", tc.name, res, tc.expected)
			}
		})
	}
}

func TestBuildSSHClientConfig_LegacyCiphers(t *testing.T) {
	modernHost := config.HostConfig{
		Name:          "modern",
		User:          "admin",
		Password:      "pass",
		LegacyCiphers: false,
	}
	cfgModern, err := buildSSHClientConfig(modernHost, 5*time.Second)
	if err != nil {
		t.Fatalf("buildSSHClientConfig failed: %v", err)
	}
	if len(cfgModern.HostKeyAlgorithms) > 0 {
		t.Errorf("Expected default host key algorithms, got %v", cfgModern.HostKeyAlgorithms)
	}

	legacyHost := config.HostConfig{
		Name:          "legacy",
		User:          "admin",
		Password:      "pass",
		LegacyCiphers: true,
	}
	cfgLegacy, err := buildSSHClientConfig(legacyHost, 5*time.Second)
	if err != nil {
		t.Fatalf("buildSSHClientConfig failed: %v", err)
	}

	// Verify legacy ciphers contains aes128-cbc and 3des-cbc
	hasCBC := false
	for _, c := range cfgLegacy.Config.Ciphers {
		if c == "aes128-cbc" {
			hasCBC = true
			break
		}
	}
	if !hasCBC {
		t.Errorf("Expected aes128-cbc in legacy ciphers, got %v", cfgLegacy.Config.Ciphers)
	}

	// Verify legacy KEX contains diffie-hellman-group1-sha1
	hasDH1 := false
	for _, k := range cfgLegacy.Config.KeyExchanges {
		if k == "diffie-hellman-group1-sha1" {
			hasDH1 = true
			break
		}
	}
	if !hasDH1 {
		t.Errorf("Expected diffie-hellman-group1-sha1 in legacy key exchanges, got %v", cfgLegacy.Config.KeyExchanges)
	}

	// Verify ssh-rsa in HostKeyAlgorithms
	hasSSHRSA := false
	for _, h := range cfgLegacy.HostKeyAlgorithms {
		if h == ssh.KeyAlgoRSA {
			hasSSHRSA = true
			break
		}
	}
	if !hasSSHRSA {
		t.Errorf("Expected ssh-rsa in HostKeyAlgorithms, got %v", cfgLegacy.HostKeyAlgorithms)
	}
}

// helper to start a mock SSH server for functional execution tests
func startTestSSHServer(t *testing.T, channelHandler func(ch ssh.Channel, requests <-chan *ssh.Request)) (string, int, func()) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, nil // accept all passwords
		},
	}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start test listener: %v", err)
	}

	tcpAddr := listener.Addr().(*net.TCPAddr)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sConn, chans, reqs, err := ssh.NewServerConn(c, serverConfig)
				if err != nil {
					c.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChannel := range chans {
					if newChannel.ChannelType() != "session" {
						newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
						continue
					}
					channel, requests, err := newChannel.Accept()
					if err != nil {
						continue
					}
					go channelHandler(channel, requests)
				}
				_ = sConn
			}(conn)
		}
	}()

	return tcpAddr.IP.String(), tcpAddr.Port, func() { listener.Close() }
}

func TestSSHRunner_ExecWithStdin(t *testing.T) {
	// Simulates MikroTik /system reboot where server prompts and checks stdin confirmation
	host, port, cleanup := startTestSSHServer(t, func(ch ssh.Channel, requests <-chan *ssh.Request) {
		defer ch.Close()
		for req := range requests {
			if req.Type == "exec" {
				req.Reply(true, nil)
				// Read command payload (length prefixed in SSH exec request)
				cmd := string(req.Payload[4:])
				if strings.Contains(cmd, "reboot") {
					// Read stdin from client
					buf := make([]byte, 16)
					n, _ := ch.Read(buf)
					input := string(buf[:n])
					if strings.HasPrefix(input, "y") {
						ch.Write([]byte("Rebooting device now...\n"))
						// Send exit status 0
						ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						return
					}
					ch.Write([]byte("Aborted by user\n"))
					ch.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
					return
				}
			}
			req.Reply(false, nil)
		}
	})
	defer cleanup()

	cm := config.NewTestConfigManager(&config.AppConfig{
		Hosts: map[string]config.HostConfig{
			"test-router": {
				Name:     "Test Router",
				Host:     host,
				Port:     port,
				User:     "admin",
				Password: "secretpassword",
			},
		},
	})

	runner := NewSSHRunner(cm)
	btn := config.ButtonConfig{
		ID:      "reboot-btn",
		Label:   "Reboot Router",
		Host:    "test-router",
		Command: "/system reboot",
		Stdin:   "y\n",
		Timeout: 5,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := runner.Execute(ctx, btn)
	if !res.Success {
		t.Fatalf("Expected success for reboot with stdin 'y\n', got failure: %s", res.ErrorDetails)
	}
	if !strings.Contains(res.Stdout, "Rebooting device now") {
		t.Errorf("Expected reboot stdout, got %q", res.Stdout)
	}
}

func TestSSHRunner_PTYShellExecution(t *testing.T) {
	// Simulates Cisco switch: rejects exec, requires pty-req + shell, outputs commands
	host, port, cleanup := startTestSSHServer(t, func(ch ssh.Channel, requests <-chan *ssh.Request) {
		defer ch.Close()
		ptyReceived := false
		for req := range requests {
			switch req.Type {
			case "exec":
				// Cisco rejects exec channels!
				req.Reply(false, nil)
			case "pty-req":
				ptyReceived = true
				req.Reply(true, nil)
			case "shell":
				if !ptyReceived {
					req.Reply(false, nil)
					return
				}
				req.Reply(true, nil)
				ch.Write([]byte("Switch> "))

				// Read commands from client stdin
				buf := make([]byte, 1024)
				for {
					n, err := ch.Read(buf)
					if err != nil {
						return
					}
					received := string(buf[:n])
					if strings.Contains(received, "show ip int brief") {
						ch.Write([]byte("FastEthernet0/1  10.0.0.1  YES  manual  up  up\r\nSwitch> "))
					}
					if strings.Contains(received, "exit") {
						ch.Write([]byte("exit\r\n"))
						ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						return
					}
				}
			default:
				req.Reply(false, nil)
			}
		}
	})
	defer cleanup()

	cm := config.NewTestConfigManager(&config.AppConfig{
		Hosts: map[string]config.HostConfig{
			"cisco-switch": {
				Name:     "Cisco Switch",
				Host:     host,
				Port:     port,
				User:     "cisco",
				Password: "ciscopassword",
				PTY:      true,
			},
		},
	})

	runner := NewSSHRunner(cm)
	btn := config.ButtonConfig{
		ID:      "show-ip-btn",
		Label:   "Show Interfaces",
		Host:    "cisco-switch",
		Command: "show ip int brief",
		PTY:     true,
		Timeout: 5,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := runner.Execute(ctx, btn)
	if !res.Success {
		t.Fatalf("Expected success for PTY shell execution, got error: %s", res.ErrorDetails)
	}
	if !strings.Contains(res.Stdout, "FastEthernet0/1") {
		t.Errorf("Expected switch interface output in stdout, got %q", res.Stdout)
	}
}

func TestSSHRunner_ExecChannelFailedDiagnosticHint(t *testing.T) {
	// Simulates Cisco switch rejecting exec when button didn't set PTY: true
	host, port, cleanup := startTestSSHServer(t, func(ch ssh.Channel, requests <-chan *ssh.Request) {
		defer ch.Close()
		for req := range requests {
			if req.Type == "exec" {
				req.Reply(false, nil) // Cisco rejects exec
				return
			}
			req.Reply(false, nil)
		}
	})
	defer cleanup()

	cm := config.NewTestConfigManager(&config.AppConfig{
		Hosts: map[string]config.HostConfig{
			"switch": {
				Name:     "Network Switch",
				Host:     host,
				Port:     port,
				User:     "cisco",
				Password: "pass",
				PTY:      false, // explicitly false
			},
		},
	})

	runner := NewSSHRunner(cm)
	btn := config.ButtonConfig{
		ID:      "failed-btn",
		Label:   "Show Version",
		Host:    "switch",
		Command: "show version",
		PTY:     false,
		Timeout: 5,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := runner.Execute(ctx, btn)
	if res.Success {
		t.Fatalf("Expected failure due to rejected exec channel")
	}
	if !strings.Contains(res.ErrorDetails, "Enable 'pty: true'") {
		t.Errorf("Expected diagnostic hint about pty: true, got %q", res.ErrorDetails)
	}
}
