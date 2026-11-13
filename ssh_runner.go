package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type ExecutionResult struct {
	ButtonID     string        `json:"button_id"`
	ButtonLabel  string        `json:"button_label"`
	HostName     string        `json:"host_name"`
	HostAddress  string        `json:"host_address"`
	Command      string        `json:"command"`
	Success      bool          `json:"success"`
	ExitCode     int           `json:"exit_code"`
	Duration     time.Duration `json:"duration"`
	Stdout       string        `json:"stdout"`
	Stderr       string        `json:"stderr"`
	ErrorDetails string        `json:"error_details"`
	ExecutedAt   time.Time     `json:"executed_at"`
}

type SSHRunner struct {
	configMgr *ConfigManager
}

func NewSSHRunner(cm *ConfigManager) *SSHRunner {
	return &SSHRunner{configMgr: cm}
}

// Execute runs the button's command on its target host
func (r *SSHRunner) Execute(ctx context.Context, btn ButtonConfig) *ExecutionResult {
	start := time.Now()
	res := &ExecutionResult{
		ButtonID:    btn.ID,
		ButtonLabel: btn.Label,
		Command:     btn.Command,
		ExecutedAt:  start,
	}

	cfg := r.configMgr.Get()
	host, exists := cfg.Hosts[btn.Host]
	if !exists {
		res.Success = false
		res.ErrorDetails = fmt.Sprintf("Target host %q not found in configuration", btn.Host)
		res.Duration = time.Since(start)
		return res
	}

	res.HostName = host.Name
	res.HostAddress = fmt.Sprintf("%s:%d", host.Host, host.Port)

	// Build SSH client configuration
	clientConfig, err := buildSSHClientConfig(host, time.Duration(btn.Timeout)*time.Second)
	if err != nil {
		res.Success = false
		res.ErrorDetails = fmt.Sprintf("SSH configuration error: %v", err)
		res.Duration = time.Since(start)
		return res
	}

	// Connect with timeout
	addr := fmt.Sprintf("%s:%d", host.Host, host.Port)
	conn, err := net.DialTimeout("tcp", addr, time.Duration(btn.Timeout)*time.Second)
	if err != nil {
		res.Success = false
		res.ErrorDetails = fmt.Sprintf("Failed to connect to %s: %v", addr, err)
		res.Duration = time.Since(start)
		return res
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, clientConfig)
	if err != nil {
		conn.Close()
		res.Success = false
		res.ErrorDetails = fmt.Sprintf("SSH handshake failed: %v", err)
		res.Duration = time.Since(start)
		return res
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		res.Success = false
		res.ErrorDetails = fmt.Sprintf("Failed to open SSH session: %v", err)
		res.Duration = time.Since(start)
		return res
	}
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	// Run with timeout handling
	done := make(chan error, 1)
	go func() {
		done <- session.Run(btn.Command)
	}()

	select {
	case <-ctx.Done():
		session.Signal(ssh.SIGKILL) // best effort
		res.Success = false
		res.ErrorDetails = "Command execution timed out"
		res.Stdout = stdoutBuf.String()
		res.Stderr = stderrBuf.String()
		res.Duration = time.Since(start)
		return res

	case runErr := <-done:
		res.Duration = time.Since(start)
		res.Stdout = stdoutBuf.String()
		res.Stderr = stderrBuf.String()

		if runErr == nil {
			res.Success = true
			res.ExitCode = 0
			return res
		}

		// Inspect error
		exitCode := 0
		var exitErr *ssh.ExitError
		var exitMissingErr *ssh.ExitMissingError

		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitStatus()
			res.ExitCode = exitCode
		}

		// Check for abrupt disconnects (reboot, shutdown, etc.)
		if isGracefulDisconnect(runErr, btn.Command) {
			res.Success = true
			res.ExitCode = 0
			if res.Stdout == "" {
				res.Stdout = "(Remote connection closed immediately. This is expected behavior for reboot or shutdown commands.)"
			}
			return res
		}

		if errors.As(runErr, &exitMissingErr) {
			// Remote server exited without sending exit status
			res.Success = true
			res.ExitCode = 0
			res.Stdout += "\n(Notice: Remote server terminated session without exit code)."
			return res
		}

		res.Success = false
		res.ErrorDetails = fmt.Sprintf("Execution failed: %v", runErr)
		return res
	}
}

func buildSSHClientConfig(host HostConfig, timeout time.Duration) (*ssh.ClientConfig, error) {
	var authMethods []ssh.AuthMethod

	// Private key authentication
	if host.KeyPath != "" {
		keyBytes, err := os.ReadFile(host.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key at %q: %w", host.KeyPath, err)
		}

		var signer ssh.Signer
		if host.KeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(host.KeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	// Password authentication
	if host.Password != "" {
		authMethods = append(authMethods, ssh.Password(host.Password))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication method provided for host %q (specify password or key_path)", host.Name)
	}

	// Host key callback
	var hostKeyCallback ssh.HostKeyCallback
	if host.InsecureIgnoreHostKey != nil && *host.InsecureIgnoreHostKey {
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	} else if host.KnownHostsPath != "" {
		cb, err := knownhosts.New(host.KnownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read known_hosts at %q: %w", host.KnownHostsPath, err)
		}
		hostKeyCallback = cb
	} else {
		// Default to insecure for ease of homelab use unless specified
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	return &ssh.ClientConfig{
		User:            host.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
	}, nil
}

// isGracefulDisconnect identifies errors caused by commands that immediately kill the SSH connection
func isGracefulDisconnect(err error, command string) bool {
	if err == nil {
		return false
	}

	cmdLower := strings.ToLower(command)
	isRebootCmd := strings.Contains(cmdLower, "reboot") ||
		strings.Contains(cmdLower, "shutdown") ||
		strings.Contains(cmdLower, "poweroff") ||
		strings.Contains(cmdLower, "init 0") ||
		strings.Contains(cmdLower, "init 6") ||
		strings.Contains(cmdLower, "halt")

	errStr := strings.ToLower(err.Error())

	// Check if the error is typical of a terminated host socket
	isSocketDrop := errors.Is(err, io.EOF) ||
		strings.Contains(errStr, "remote command exited without exit status") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "closed by remote host") ||
		strings.Contains(errStr, "use of closed network connection")

	return isRebootCmd && isSocketDrop
}
