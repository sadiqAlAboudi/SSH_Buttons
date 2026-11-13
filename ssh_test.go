package main

import (
	"errors"
	"io"
	"testing"
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
