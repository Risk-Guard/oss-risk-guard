package dag_builder

import (
	"testing"
)

type mockDeprecatedCheck struct{}

func (m *mockDeprecatedCheck) GetDeprecated() bool { return true }

type mockNonDeprecatedCheck struct{}

func (m *mockNonDeprecatedCheck) GetDeprecated() bool { return false }

type mockNoDeprecatedInterface struct{}

func TestIsDeprecated(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected bool
	}{
		{"deprecated check returns true", &mockDeprecatedCheck{}, true},
		{"non-deprecated check returns false", &mockNonDeprecatedCheck{}, false},
		{"type without interface returns false", &mockNoDeprecatedInterface{}, false},
		{"nil returns false", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDeprecated(tt.input); got != tt.expected {
				t.Errorf("IsDeprecated() = %v, want %v", got, tt.expected)
			}
		})
	}
}
