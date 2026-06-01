package main

import (
	"testing"

	"github.com/fatih/color"
)

func TestResolveColor(t *testing.T) {
	cases := []struct {
		name      string
		colorMode string
		noColor   bool
		want      bool // expected color.NoColor
		wantErr   bool
	}{
		{"always forces color on", "always", false, false, false},
		{"always beats --no-color", "always", true, false, false},
		{"never disables", "never", false, true, false},
		{"auto + no-color disables", "auto", true, true, false},
		{"auto without no-color leaves false", "auto", false, false, false},
		{"empty treated as auto", "", true, true, false},
		{"invalid value errors", "sometimes", false, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prev := color.NoColor
			t.Cleanup(func() { color.NoColor = prev })
			color.NoColor = false

			err := resolveColor(c.colorMode, c.noColor)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", c.colorMode)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if color.NoColor != c.want {
				t.Errorf("color.NoColor = %v, want %v", color.NoColor, c.want)
			}
		})
	}
}
