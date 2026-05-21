package main

import "testing"

func TestParsePackageKey(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		wantEco     string
		wantName    string
		wantVersion *string
		wantErr     bool
	}{
		{
			name:     "bare key",
			key:      "package/npm/express",
			wantEco:  "npm",
			wantName: "express",
		},
		{
			name:        "key with version",
			key:         "package/npm/lodash?version=4.17.20",
			wantEco:     "npm",
			wantName:    "lodash",
			wantVersion: strPtr("4.17.20"),
		},
		{
			name:        "key with URL-escaped version",
			key:         "package/npm/foo?version=1.0.0%2Bbuild",
			wantEco:     "npm",
			wantName:    "foo",
			wantVersion: strPtr("1.0.0+build"),
		},
		{
			name:    "invalid key (no package prefix)",
			key:     "source/github.com/foo/bar",
			wantErr: true,
		},
		{
			name:    "empty ecosystem",
			key:     "package//express",
			wantErr: true,
		},
		{
			name:    "missing name",
			key:     "package/npm/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eco, name, version, err := parsePackageKey(tt.key)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eco != tt.wantEco {
				t.Errorf("ecosystem = %q, want %q", eco, tt.wantEco)
			}
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			switch {
			case tt.wantVersion == nil && version != nil:
				t.Errorf("version = %q, want nil", *version)
			case tt.wantVersion != nil && version == nil:
				t.Errorf("version = nil, want %q", *tt.wantVersion)
			case tt.wantVersion != nil && version != nil && *tt.wantVersion != *version:
				t.Errorf("version = %q, want %q", *version, *tt.wantVersion)
			}
		})
	}
}

func strPtr(s string) *string { return &s }
