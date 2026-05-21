package setupcfg

import "testing"

func TestParseName(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantName    string
		wantDynamic bool
	}{
		{
			name: "simple name",
			content: `[metadata]
name = flake8
version = 1.0.0`,
			wantName:    "flake8",
			wantDynamic: false,
		},
		{
			name: "no metadata section",
			content: `[options]
packages = find:`,
			wantName:    "",
			wantDynamic: false,
		},
		{
			name: "dynamic attr name",
			content: `[metadata]
name = attr:mypackage.__version__`,
			wantName:    "",
			wantDynamic: true,
		},
		{
			name: "dynamic file name",
			content: `[metadata]
name = file:NAME.txt`,
			wantName:    "",
			wantDynamic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseName(tt.content)

			if tt.wantName == "" {
				if result.Name != nil {
					t.Errorf("expected nil Name, got %q", *result.Name)
				}
			} else {
				if result.Name == nil {
					t.Errorf("expected Name=%q, got nil", tt.wantName)
				} else if *result.Name != tt.wantName {
					t.Errorf("expected Name=%q, got %q", tt.wantName, *result.Name)
				}
			}

			if result.IsDynamic != tt.wantDynamic {
				t.Errorf("expected IsDynamic=%v, got %v", tt.wantDynamic, result.IsDynamic)
			}
		})
	}
}
