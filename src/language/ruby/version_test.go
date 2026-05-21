package ruby

import (
	"testing"
)

func TestCompareVersions(t *testing.T) {
	rb := &Ruby{}

	tests := []struct {
		name    string
		a       string
		b       string
		want    int
		wantErr bool
	}{
		{"less than", "1.0.0", "2.0.0", -1, false},
		{"equal", "1.0.0", "1.0.0", 0, false},
		{"greater than", "2.0.0", "1.0.0", 1, false},
		{"prerelease less than release", "1.0.0.alpha", "1.0.0", -1, false},
		{"patch version comparison", "1.0.1", "1.0.0", 1, false},
		{"minor version comparison", "1.1.0", "1.0.0", 1, false},
		{"invalid version a", "not-a-version", "1.0.0", 0, true},
		{"invalid version b", "1.0.0", "not-a-version", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rb.CompareVersions(tt.a, tt.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompareVersions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
