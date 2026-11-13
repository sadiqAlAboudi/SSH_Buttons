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
		hint := ""
		if strings.Contains(strings.ToLower(err.Error()), "no common algorithm") {
			hint = " (Hint: Remote device requires legacy algorithms. Try adding 'legacy_ciphers: true' to this host in config.yml)."
		}
		res.ErrorDetails = fmt.Sprintf("SSH handshake failed: %v%s", err, hint)
		res.Duration = time.Since(start)
		return res
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	if btn.PTY {
		return r.executePTY(ctx, client, btn, host, start)
	}

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

	if btn.Stdin != "" {
		session.Stdin = strings.NewReader(btn.Stdin)
	}

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
		hint := ""
		errLower := strings.ToLower(runErr.Error())
		if strings.Contains(errLower, "channel request failed") ||
			(strings.Contains(errLower, "command") && strings.Contains(errLower, "failed")) ||
			strings.Contains(errLower, "channel open: rejected") {
			hint = "\n(Hint: This device may not support non-interactive 'exec' commands. Enable 'pty: true' in config.yml for this host or button)."
		}
		res.ErrorDetails = fmt.Sprintf("Execution failed: %v%s", runErr, hint)
		return res
	}
}

// executePTY runs commands in an interactive pseudo-terminal shell session (required by Cisco IOS and switches)
func (r *SSHRunner) executePTY(ctx context.Context, client *ssh.Client, btn ButtonConfig, host HostConfig, start time.Time) *ExecutionResult {
	res := &ExecutionResult{
		ButtonID:    btn.ID,
		ButtonLabel: btn.Label,
		HostName:    host.Name,
		HostAddress: fmt.Sprintf("%s:%d", host.Host, host.Port),
		Command:     btn.Command,
		ExecutedAt:  start,
	}

	session, err := client.NewSession()
	if err != nil {
		res.Success = false
		res.ErrorDetails = fmt.Sprintf("Failed to open SSH session: %v", err)
		res.Duration = time.Since(start)
		return res
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0, // disable local echo
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("vt100", 80, 40, modes); err != nil {
		res.Success = false
		res.ErrorDetails = fmt.Sprintf("Failed to request PTY: %v", err)
		res.Duration = time.Since(start)
		return res
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	stdinPipe, err := session.StdinPipe()
	if err != nil {
		res.Success = false
		res.ErrorDetails = fmt.Sprintf("Failed to acquire stdin pipe: %v", err)
		res.Duration = time.Since(start)
		return res
	}

	if err := session.Shell(); err != nil {
		res.Success = false
		res.ErrorDetails = fmt.Sprintf("Failed to start shell: %v", err)
		res.Duration = time.Since(start)
		return res
	}

	// Prepare commands: normalize line breaks and send each command line
	cmdToSend := strings.ReplaceAll(btn.Command, "\r\n", "\n")
	lines := strings.Split(cmdToSend, "\n")

	done := make(chan error, 1)
	go func() {
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			_, _ = io.WriteString(stdinPipe, line+"\r\n")
			time.Sleep(150 * time.Millisecond)
		}

		// Send any secondary stdin confirmation input (e.g. Cisco reload [confirm])
		if btn.Stdin != "" {
			time.Sleep(200 * time.Millisecond)
			stdinText := strings.ReplaceAll(btn.Stdin, "\r\n", "\n")
			stdinLines := strings.Split(stdinText, "\n")
			for _, sl := range stdinLines {
				if sl != "" {
					_, _ = io.WriteString(stdinPipe, sl+"\r\n")
				} else {
					_, _ = io.WriteString(stdinPipe, "\r\n")
				}
				time.Sleep(100 * time.Millisecond)
			}
		}

		// Unless it is a reload/reboot command or user already typed exit, send exit to close the shell cleanly
		cmdLower := strings.ToLower(btn.Command)
		if !strings.Contains(cmdLower, "exit") && !isRebootCommand(btn.Command) {
			_, _ = io.WriteString(stdinPipe, "exit\r\n")
		}
		_ = stdinPipe.Close()

		done <- session.Wait()
	}()

	select {
	case <-ctx.Done():
		session.Signal(ssh.SIGKILL)
		res.Success = false
		res.ErrorDetails = "Command execution timed out"
		res.Stdout = cleanPTYOutput(stdoutBuf.String() + "\n" + stderrBuf.String())
		res.Duration = time.Since(start)
		return res

	case waitErr := <-done:
		res.Duration = time.Since(start)
		res.Stdout = cleanPTYOutput(stdoutBuf.String() + "\n" + stderrBuf.String())

		if waitErr == nil {
			res.Success = true
			res.ExitCode = 0
			return res
		}

		// Check for graceful disconnects on reboot/reload
		if isGracefulDisconnect(waitErr, btn.Command) {
			res.Success = true
			res.ExitCode = 0
			if res.Stdout == "" {
				res.Stdout = "(Remote connection closed immediately. This is expected behavior for reboot or reload commands.)"
			}
			return res
		}

		var exitErr *ssh.ExitError
		var exitMissingErr *ssh.ExitMissingError
		if errors.As(waitErr, &exitErr) {
			res.ExitCode = exitErr.ExitStatus()
		} else if errors.As(waitErr, &exitMissingErr) {
			res.Success = true
			res.ExitCode = 0
			return res
		}

		// In PTY mode, remote network devices often terminate session with EOF on exit
		if errors.Is(waitErr, io.EOF) || strings.Contains(strings.ToLower(waitErr.Error()), "eof") {
			res.Success = true
			res.ExitCode = 0
			return res
		}

		res.Success = false
		res.ErrorDetails = fmt.Sprintf("Execution failed: %v", waitErr)
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

	var config ssh.Config
	config.SetDefaults()

	if host.LegacyCiphers {
		// Enable legacy ciphers & key exchanges for older network gear (Cisco Catalyst, RouterOS v6, etc.)
		config.Ciphers = []string{
			"aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com",
			"aes128-ctr", "aes192-ctr", "aes256-ctr",
			"aes128-cbc", "aes256-cbc", "3des-cbc",
		}
		config.KeyExchanges = []string{
			"mlkem768x25519-sha256", "curve25519-sha256", "curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
			"diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1",
			"diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group-exchange-sha256",
		}
	}

	clientConfig := &ssh.ClientConfig{
		User:            host.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
		Config:          config,
	}

	if host.LegacyCiphers {
		// Include ssh-rsa (SHA-1 signatures) for legacy switches/appliances
		clientConfig.HostKeyAlgorithms = []string{
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoECDSA256,
			ssh.KeyAlgoECDSA384,
			ssh.KeyAlgoECDSA521,
			ssh.KeyAlgoRSASHA512,
			ssh.KeyAlgoRSASHA256,
			ssh.KeyAlgoRSA,
		}
	}

	return clientConfig, nil
}

// cleanPTYOutput strips terminal noise and normalizes carriage returns
func cleanPTYOutput(raw string) string {
	s := strings.ReplaceAll(raw, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "")
	return strings.TrimSpace(s)
}

// isRebootCommand checks if command is meant to reboot, reload, or halt a server/device
func isRebootCommand(cmd string) bool {
	cmdLower := strings.ToLower(cmd)
	return strings.Contains(cmdLower, "reboot") ||
		strings.Contains(cmdLower, "shutdown") ||
		strings.Contains(cmdLower, "poweroff") ||
		strings.Contains(cmdLower, "reload") ||
		strings.Contains(cmdLower, "init 0") ||
		strings.Contains(cmdLower, "init 6") ||
		strings.Contains(cmdLower, "halt")
}

// isGracefulDisconnect identifies errors caused by commands that immediately kill the SSH connection
func isGracefulDisconnect(err error, command string) bool {
	if err == nil {
		return false
	}

	if !isRebootCommand(command) {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// Check if the error is typical of a terminated host socket
	return errors.Is(err, io.EOF) ||
		strings.Contains(errStr, "remote command exited without exit status") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "closed by remote host") ||
		strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "eof")
}
