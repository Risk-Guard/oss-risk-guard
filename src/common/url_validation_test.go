package common

import (
	"strings"
	"testing"
)

func TestValidateRemoteURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		// Valid URLs - only https://
		{
			name:    "valid https github",
			url:     "https://github.com/owner/repo",
			wantErr: false,
		},
		{
			name:    "valid https gitlab",
			url:     "https://gitlab.com/owner/repo",
			wantErr: false,
		},
		{
			name:    "valid https with .git",
			url:     "https://github.com/owner/repo.git",
			wantErr: false,
		},
		{
			name:    "valid https with path",
			url:     "https://example.com/path/to/repo",
			wantErr: false,
		},
		{
			name:    "valid https with port",
			url:     "https://example.com:8443/repo",
			wantErr: false,
		},

		// Valid - git+https://
		{
			name:    "valid git+https github",
			url:     "git+https://github.com/owner/repo.git",
			wantErr: false,
		},
		{
			name:    "valid git+https gitlab",
			url:     "git+https://gitlab.com/owner/repo",
			wantErr: false,
		},

		// Invalid - git+http:// (insecure)
		{
			name:    "git+http insecure",
			url:     "git+http://github.com/owner/repo",
			wantErr: true,
			errMsg:  "git+http:// is insecure",
		},

		// Invalid - empty
		{
			name:    "empty URL",
			url:     "",
			wantErr: true,
			errMsg:  "empty URL",
		},

		// Invalid - http (insecure)
		{
			name:    "http insecure",
			url:     "http://github.com/owner/repo",
			wantErr: true,
			errMsg:  "http:// is insecure",
		},
		{
			name:    "http with .git",
			url:     "http://example.com/repo.git",
			wantErr: true,
			errMsg:  "http:// is insecure",
		},

		// Invalid - file protocol
		{
			name:    "file protocol lowercase",
			url:     "file:///etc/passwd",
			wantErr: true,
			errMsg:  "file:// protocol not allowed",
		},
		{
			name:    "file protocol uppercase",
			url:     "FILE:///etc/passwd",
			wantErr: true,
			errMsg:  "file:// protocol not allowed",
		},
		{
			name:    "file protocol mixed case",
			url:     "FiLe:///etc/passwd",
			wantErr: true,
			errMsg:  "file:// protocol not allowed",
		},

		// Invalid - git protocol
		{
			name:    "git protocol",
			url:     "git://github.com/owner/repo",
			wantErr: true,
			errMsg:  "git:// protocol not supported",
		},

		// Invalid - ssh protocol
		{
			name:    "ssh protocol",
			url:     "ssh://git@github.com/owner/repo",
			wantErr: true,
			errMsg:  "ssh:// protocol not supported",
		},

		// Invalid - git@ (SCP-style SSH)
		{
			name:    "git@ SSH style",
			url:     "git@github.com:owner/repo.git",
			wantErr: true,
			errMsg:  "git@ SSH URLs not supported",
		},

		// Invalid - ftp
		{
			name:    "ftp protocol",
			url:     "ftp://example.com/repo",
			wantErr: true,
			errMsg:  "ftp:// protocol not supported",
		},

		// Invalid - data URI
		{
			name:    "data URI",
			url:     "data:text/plain,malicious",
			wantErr: true,
			errMsg:  "missing protocol",
		},

		// Invalid - localhost
		{
			name:    "localhost",
			url:     "https://localhost/repo",
			wantErr: true,
			errMsg:  "localhost URLs not allowed",
		},
		{
			name:    "localhost with port",
			url:     "https://localhost:8080/repo",
			wantErr: true,
			errMsg:  "localhost URLs not allowed",
		},
		{
			name:    "127.0.0.1",
			url:     "https://127.0.0.1/repo",
			wantErr: true,
			errMsg:  "localhost URLs not allowed",
		},
		{
			name:    "127.0.0.1 with port",
			url:     "https://127.0.0.1:8080/repo",
			wantErr: true,
			errMsg:  "localhost URLs not allowed",
		},
		{
			name:    "127.x.x.x range",
			url:     "https://127.1.2.3/repo",
			wantErr: true,
			errMsg:  "localhost URLs not allowed",
		},
		{
			name:    "IPv6 loopback ::1",
			url:     "https://[::1]/repo",
			wantErr: true,
			errMsg:  "localhost URLs not allowed",
		},
		{
			name:    "0.0.0.0",
			url:     "https://0.0.0.0/repo",
			wantErr: true,
			errMsg:  "localhost URLs not allowed",
		},

		// Invalid - command injection
		{
			name:    "git flag upload-pack",
			url:     "https://github.com/repo --upload-pack=evil",
			wantErr: true,
			errMsg:  "contains git flags",
		},
		{
			name:    "git flag arbitrary",
			url:     "https://example.com/repo --config=malicious",
			wantErr: true,
			errMsg:  "contains git flags",
		},

		// Invalid - path traversal
		{
			name:    "path traversal double dot",
			url:     "https://github.com/../../etc/passwd",
			wantErr: true,
			errMsg:  "path traversal detected",
		},
		{
			name:    "path traversal in middle",
			url:     "https://github.com/owner/../../../etc/passwd",
			wantErr: true,
			errMsg:  "path traversal detected",
		},

		// Invalid - missing protocol
		{
			name:    "no protocol",
			url:     "github.com/owner/repo",
			wantErr: true,
			errMsg:  "missing protocol",
		},

		// Invalid - malformed
		{
			name:    "null byte",
			url:     "https://github.com\x00evil",
			wantErr: true,
			errMsg:  "invalid URL format",
		},
		{
			name:    "invalid URL characters",
			url:     "ht!tp://invalid url",
			wantErr: true,
			errMsg:  "invalid URL format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRemoteURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRemoteURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" {
				if err == nil {
					t.Errorf("ValidateRemoteURL() expected error containing %q, got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateRemoteURL() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func TestValidateAndNormalizeURL(t *testing.T) {
	tests := []struct {
		name        string
		rawURL      string
		wantNorm    string
		wantFinding bool
		wantErr     bool
	}{
		{
			name:     "clean https URL passes through",
			rawURL:   "https://github.com/owner/repo",
			wantNorm: "https://github.com/owner/repo",
		},
		{
			name:        "git:// on known host normalizes with finding",
			rawURL:      "git://github.com/substack/text-table.git",
			wantNorm:    "https://github.com/substack/text-table",
			wantFinding: true,
		},
		{
			name:        "http:// on known host normalizes with finding",
			rawURL:      "http://github.com/owner/repo",
			wantNorm:    "https://github.com/owner/repo",
			wantFinding: true,
		},
		{
			name:        "git@ on known host normalizes with finding",
			rawURL:      "git@github.com:owner/repo.git",
			wantNorm:    "https://github.com/owner/repo",
			wantFinding: true,
		},
		{
			name:    "git:// on unknown host is hard rejection",
			rawURL:  "git://unknown-host.com/repo",
			wantErr: true,
		},
		{
			name:    "http:// on unknown host is hard rejection",
			rawURL:  "http://unknown-host.com/repo",
			wantErr: true,
		},
		{
			name:     "git+https normalizes cleanly",
			rawURL:   "git+https://github.com/owner/repo.git",
			wantNorm: "https://github.com/owner/repo",
		},
		{
			name:     "https with .git suffix normalizes cleanly",
			rawURL:   "https://github.com/owner/repo.git",
			wantNorm: "https://github.com/owner/repo",
		},
		{
			name:        "git:// on gitlab normalizes with finding",
			rawURL:      "git://gitlab.com/owner/repo.git",
			wantNorm:    "https://gitlab.com/owner/repo",
			wantFinding: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized, finding, err := ValidateAndNormalizeURL(tt.rawURL)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if normalized != tt.wantNorm {
				t.Errorf("normalized = %q, want %q", normalized, tt.wantNorm)
			}
			if tt.wantFinding && finding == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantFinding && finding != nil {
				t.Errorf("unexpected finding: %q", *finding)
			}
		})
	}
}

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want bool
	}{
		{"localhost", "localhost", true},
		{"localhost with port", "localhost:8080", true},
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.1 with port", "127.0.0.1:8080", true},
		{"127.x.x.x range", "127.1.2.3", true},
		{"::1 IPv6", "::1", true},
		{"[::1] bracketed", "[::1]", true},
		{"[::1]:8080 with port", "[::1]:8080", true},
		{"0.0.0.0", "0.0.0.0", true},
		{"0.0.0.0 with port", "0.0.0.0:8080", true},
		{"empty host", "", true},
		{"github.com", "github.com", false},
		{"example.com", "example.com", false},
		{"192.168.1.1", "192.168.1.1", false},
		{"10.0.0.1", "10.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLocalhost(tt.host); got != tt.want {
				t.Errorf("isLocalhost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}
