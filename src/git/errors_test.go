package git

import (
	"strings"
	"testing"
)

func TestValidateGitRef(t *testing.T) {
	tests := []struct {
		name        string
		ref         string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid commit SHA",
			ref:     "abc123def456",
			wantErr: false,
		},
		{
			name:    "valid full SHA",
			ref:     "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
			wantErr: false,
		},
		{
			name:    "valid branch name",
			ref:     "main",
			wantErr: false,
		},
		{
			name:    "valid branch with slash",
			ref:     "feature/new-thing",
			wantErr: false,
		},
		{
			name:    "valid tag with v prefix",
			ref:     "v1.2.3",
			wantErr: false,
		},
		{
			name:    "valid tag with underscore",
			ref:     "release_1.0",
			wantErr: false,
		},
		{
			name:    "valid tag with dot",
			ref:     "v1.0.0-beta.1",
			wantErr: false,
		},
		{
			name:    "valid nested branch",
			ref:     "refs/heads/feature/branch",
			wantErr: false,
		},
		{
			name:        "empty ref",
			ref:         "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "ref starting with dash",
			ref:         "-branch",
			wantErr:     true,
			errContains: "cannot start with dash",
		},
		{
			name:        "ref with option injection",
			ref:         "--upload-pack=evil",
			wantErr:     true,
			errContains: "cannot start with dash",
		},
		{
			name:        "ref with semicolon",
			ref:         "main;rm -rf /",
			wantErr:     true,
			errContains: "invalid characters",
		},
		{
			name:        "ref with space",
			ref:         "main branch",
			wantErr:     true,
			errContains: "invalid characters",
		},
		{
			name:        "ref with shell redirect",
			ref:         "main>file",
			wantErr:     true,
			errContains: "invalid characters",
		},
		{
			name:        "ref with pipe",
			ref:         "main|cat",
			wantErr:     true,
			errContains: "invalid characters",
		},
		{
			name:        "ref with backtick",
			ref:         "main`whoami`",
			wantErr:     true,
			errContains: "invalid characters",
		},
		{
			name:        "ref with dollar sign",
			ref:         "main$PATH",
			wantErr:     true,
			errContains: "invalid characters",
		},
		{
			name:        "ref with ampersand",
			ref:         "main&&evil",
			wantErr:     true,
			errContains: "invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGitRef(tt.ref)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestClassifyCloneError_TransientPatterns(t *testing.T) {
	transientCases := []struct {
		name   string
		errMsg string
	}{
		{"connection refused", "fatal: unable to access 'https://github.com/foo/bar.git/': Failed to connect to github.com port 443: Connection refused"},
		{"connection reset", "fatal: unable to access 'https://github.com/foo/bar.git/': Recv failure: Connection reset by peer"},
		{"connection timed out", "fatal: unable to access 'https://github.com/foo/bar.git/': Connection timed out after 30001 milliseconds"},
		{"temp dns failure", "fatal: unable to access 'https://github.com/foo/bar.git/': Temporary failure in name resolution"},
		{"network unreachable", "fatal: unable to access 'https://github.com/foo/bar.git/': Network is unreachable"},
		{"no route", "fatal: unable to access 'https://github.com/foo/bar.git/': No route to host"},
		{"failed to connect", "fatal: unable to access 'https://github.com/foo/bar.git/': Failed to connect to github.com port 443 after 21026 ms: Couldn't connect to server"},
		{"ssl handshake", "fatal: unable to access 'https://github.com/foo/bar.git/': SSL handshake failed"},
		{"tls handshake", "fatal: unable to access 'https://github.com/foo/bar.git/': TLS handshake failed"},
		{"gnutls error", "fatal: unable to access 'https://github.com/foo/bar.git/': gnutls_handshake() failed"},
		{"couldn't connect", "fatal: unable to access 'https://github.com/foo/bar.git/': Couldn't connect to server"},
	}

	for _, tc := range transientCases {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyCloneError("https://github.com/foo/bar", newTestError(tc.errMsg))
			cloneErr, ok := err.(*CloneError)
			if !ok {
				t.Fatalf("expected *CloneError, got %T", err)
			}
			if cloneErr.Type != ErrTypeNetworkTransient {
				t.Errorf("expected type %q, got %q", ErrTypeNetworkTransient, cloneErr.Type)
			}
			if cloneErr.GitOutput == "" {
				t.Error("expected GitOutput to be populated")
			}
		})
	}
}

func TestClassifyCloneError_PermanentPatterns(t *testing.T) {
	permanentCases := []struct {
		name         string
		errMsg       string
		expectedType string
	}{
		{"dns failure", "fatal: unable to access 'https://githubdd.com/foo/bar.git/': Could not resolve host: githubdd.com", ErrTypeNotFound},
		{"dns name not known", "fatal: unable to access 'https://githubdd.com/foo/bar.git/': Name or service not known", ErrTypeNotFound},
		{"404 not found", "fatal: repository 'https://github.com/foo/bar.git/' not found", ErrTypeNotFound},
		{"explicit 404", "fatal: unable to access 'https://github.com/foo/bar.git/': The requested URL returned error: 404", ErrTypeNotFound},
		{"authentication required", "fatal: could not read Username for 'https://github.com': terminal prompts disabled", ErrTypePrivateRepo},
		{"authentication failed", "fatal: Authentication failed for 'https://github.com/foo/bar.git/'", ErrTypePrivateRepo},
		{"401 error", "fatal: unable to access 'https://github.com/foo/bar.git/': The requested URL returned error: 401", ErrTypePrivateRepo},
		{"403 error", "fatal: unable to access 'https://github.com/foo/bar.git/': The requested URL returned error: 403", ErrTypePrivateRepo},
	}

	for _, tc := range permanentCases {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyCloneError("https://github.com/foo/bar", newTestError(tc.errMsg))
			cloneErr, ok := err.(*CloneError)
			if !ok {
				t.Fatalf("expected *CloneError, got %T", err)
			}
			if cloneErr.Type != tc.expectedType {
				t.Errorf("expected type %q, got %q", tc.expectedType, cloneErr.Type)
			}
			if cloneErr.GitOutput == "" {
				t.Error("expected GitOutput to be populated")
			}
		})
	}
}

func TestSanitizeGitOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no token",
			input:    "fatal: repository 'https://github.com/foo/bar.git/' not found",
			expected: "fatal: repository 'https://github.com/foo/bar.git/' not found",
		},
		{
			name:     "github token in url",
			input:    "fatal: unable to access 'https://x-access-token:ghp_secret123@github.com/foo/bar.git/': The requested URL returned error: 404",
			expected: "fatal: unable to access 'https://[REDACTED]@github.com/foo/bar.git/': The requested URL returned error: 404",
		},
		{
			name:     "basic auth in url",
			input:    "fatal: unable to access 'https://user:password123@github.com/foo/bar.git/': not found",
			expected: "fatal: unable to access 'https://[REDACTED]@github.com/foo/bar.git/': not found",
		},
		{
			name:     "http url with token",
			input:    "http://user:token@example.com/repo",
			expected: "http://[REDACTED]@example.com/repo",
		},
		{
			name:     "token only auth (no colon)",
			input:    "fatal: unable to access 'https://ghp_secret123@github.com/foo/bar.git/': not found",
			expected: "fatal: unable to access 'https://[REDACTED]@github.com/foo/bar.git/': not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := sanitizeGitOutput(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestExtractGitErrorLine(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single fatal line",
			input:    "fatal: repository not found",
			expected: "fatal: repository not found",
		},
		{
			name:     "multiline with fatal",
			input:    "Cloning into 'repo'...\nfatal: repository 'https://github.com/foo/bar.git/' not found\n",
			expected: "fatal: repository 'https://github.com/foo/bar.git/' not found",
		},
		{
			name:     "multiline with error",
			input:    "Cloning into 'repo'...\nerror: RPC failed; curl 56 Recv failure: Connection reset by peer\nfatal: the remote end hung up unexpectedly",
			expected: "error: RPC failed; curl 56 Recv failure: Connection reset by peer",
		},
		{
			name:     "no fatal or error",
			input:    "Some random output\nAnother line",
			expected: "Another line",
		},
		{
			name:     "all empty lines",
			input:    "\n\n\n",
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractGitErrorLine(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func newTestError(msg string) error {
	return &testError{msg: msg}
}
