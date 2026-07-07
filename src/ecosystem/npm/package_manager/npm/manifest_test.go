package npm

import (
	"testing"
)

func TestParsePackageJSON_UTF8BOM(t *testing.T) {
	// A leading UTF-8 BOM (as shipped by e.g. vite's utf8-bom-package fixture)
	// is valid to npm/Node and must not be reported as malformed metadata.
	content := "\xef\xbb\xbf" + `{
		"name": "@vitejs/test-utf8-bom-package",
		"private": true,
		"dependencies": {
			"express": "^4.18.0"
		}
	}`

	deps, pkg, err := ParsePackageJSON(content, "package.json")
	if err != nil {
		t.Fatalf("unexpected error parsing BOM-prefixed package.json: %v", err)
	}
	if pkg.Name != "@vitejs/test-utf8-bom-package" {
		t.Errorf("expected name to parse, got %q", pkg.Name)
	}
	if len(deps) != 1 {
		t.Errorf("expected 1 dependency, got %d", len(deps))
	}
}

func TestParsePackageJSON_PrivateTrue(t *testing.T) {
	content := `{
		"name": "my-private-app",
		"private": true,
		"dependencies": {
			"express": "^4.18.0"
		}
	}`

	deps, pkg, err := ParsePackageJSON(content, "package.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pkg.Private {
		t.Error("expected pkg.Private to be true")
	}
	if len(deps) != 1 {
		t.Errorf("expected 1 dependency, got %d", len(deps))
	}
}

func TestParsePackageJSON_PrivateFalse(t *testing.T) {
	content := `{
		"name": "my-public-lib",
		"dependencies": {
			"lodash": "^4.17.0"
		}
	}`

	_, pkg, err := ParsePackageJSON(content, "package.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkg.Private {
		t.Error("expected pkg.Private to be false when not specified")
	}
}

func TestParsePackageJSON_DevFlag(t *testing.T) {
	content := `{
		"name": "my-app",
		"dependencies": {
			"express": "^4.18.0"
		},
		"devDependencies": {
			"jest": "^29.0.0"
		}
	}`

	deps, _, err := ParsePackageJSON(content, "package.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	for _, dep := range deps {
		switch dep.GetName() {
		case "express":
			if dep.Dev {
				t.Error("expected express Dev=false")
			}
		case "jest":
			if !dep.Dev {
				t.Error("expected jest Dev=true")
			}
		default:
			t.Errorf("unexpected dep: %s", dep.GetName())
		}
	}
}

func TestParsePackageJSON_DevFlag_OverlapProductionWins(t *testing.T) {
	content := `{
		"name": "my-app",
		"dependencies": {
			"lodash": "^4.17.0"
		},
		"devDependencies": {
			"lodash": "^4.17.0",
			"eslint": "^8.0.0"
		}
	}`

	deps, _, err := ParsePackageJSON(content, "package.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps (lodash once + eslint), got %d", len(deps))
	}

	for _, dep := range deps {
		switch dep.GetName() {
		case "lodash":
			if dep.Dev {
				t.Error("expected lodash Dev=false (production wins)")
			}
		case "eslint":
			if !dep.Dev {
				t.Error("expected eslint Dev=true")
			}
		default:
			t.Errorf("unexpected dep: %s", dep.GetName())
		}
	}
}
