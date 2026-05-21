package registry

import (
	"fmt"
	"risk-guard/src/language"
	"risk-guard/src/language/javascript"
	"risk-guard/src/language/metadata"
	"risk-guard/src/language/python"
	"risk-guard/src/language/ruby"
	"sort"

	executiondag "risk-guard/src/execution-dag"
)

var metadataMap = map[string]metadata.Metadata{
	"npm": {
		Ecosystem:   "npm",
		DisplayName: "JavaScript (NPM)",
		Source: executiondag.Source{
			Name:        "NPM Registry",
			URL:         "https://registry.npmjs.org",
			Description: "Package registry for JavaScript (NPM)",
			Category:    executiondag.SourceCategoryRegistry,
		},
		OSVEcosystem:         "npm",
		GHSAEcosystem:        "npm",
		PackageURLFormat:     "%s/%s",
		PackagePageURLFormat: "https://www.npmjs.com/package/%s",
	},
	"pypi": {
		Ecosystem:   "pypi",
		DisplayName: "Python (PyPI)",
		Source: executiondag.Source{
			Name:        "PyPI Registry",
			URL:         "https://pypi.org/pypi",
			Description: "Package registry for Python (PyPI)",
			Category:    executiondag.SourceCategoryRegistry,
		},
		OSVEcosystem:         "PyPI",
		GHSAEcosystem:        "pip",
		PackageURLFormat:     "%s/%s/json",
		PackagePageURLFormat: "https://pypi.org/project/%s",
	},
	"rubygems": {
		Ecosystem:   "rubygems",
		DisplayName: "Ruby (RubyGems)",
		Source: executiondag.Source{
			Name:        "RubyGems Registry",
			URL:         "https://rubygems.org",
			Description: "Package registry for Ruby (RubyGems)",
			Category:    executiondag.SourceCategoryRegistry,
		},
		OSVEcosystem:         "RubyGems",
		GHSAEcosystem:        "rubygems",
		PackageURLFormat:     "%s/api/v1/gems/%s.json",
		PackagePageURLFormat: "https://rubygems.org/gems/%s",
	},
}

// Get retrieves language metadata by ecosystem name.
func Get(ecosystem string) (metadata.Metadata, error) {
	if meta, ok := metadataMap[ecosystem]; ok {
		return meta, nil
	}
	return metadata.Metadata{}, fmt.Errorf("unsupported ecosystem: %q", ecosystem)
}

// MustGet is like Get but panics if the ecosystem is not found.
// Useful for initialization code where the ecosystem should definitely exist.
func MustGet(ecosystem string) metadata.Metadata {
	meta, err := Get(ecosystem)
	if err != nil {
		panic(err)
	}
	return meta
}

// MustGetLanguage retrieves a language implementation from the provided map.
// Panics if the ecosystem is not found in the map.
// This is similar to regexp.MustCompile - it should only panic on programming errors.
func MustGetLanguage(languages map[string]language.Language, ecosystem string) language.Language {
	lang, ok := languages[ecosystem]
	if !ok {
		panic(fmt.Sprintf("language implementation not found for ecosystem: %q", ecosystem))
	}
	return lang
}

// GetLanguage retrieves a language implementation by ecosystem name.
// Creates a new instance on each call (pure function, no shared state).
func GetLanguage(ecosystem string) (language.Language, error) {
	meta, err := Get(ecosystem)
	if err != nil {
		return nil, err
	}

	switch ecosystem {
	case "npm":
		return javascript.New(&meta), nil
	case "pypi":
		return python.New(&meta), nil
	case "rubygems":
		return ruby.New(&meta), nil
	default:
		panic(fmt.Sprintf("ecosystem %q exists in metadataMap but has no implementation in GetLanguage() switch - this is a bug", ecosystem))
	}
}

// Languages returns a map of all language implementations.
// Creates fresh instances on each call (pure function, no shared state).
func Languages() map[string]language.Language {
	result := make(map[string]language.Language)
	for ecosystem, meta := range metadataMap {
		switch ecosystem {
		case "npm":
			result[ecosystem] = javascript.New(&meta)
		case "pypi":
			result[ecosystem] = python.New(&meta)
		case "rubygems":
			result[ecosystem] = ruby.New(&meta)
		default:
			panic(fmt.Sprintf("ecosystem %q exists in metadataMap but has no implementation in Languages() switch - this is a bug", ecosystem))
		}
	}
	return result
}

// Ecosystems returns a sorted list of all supported ecosystem names.
func Ecosystems() []string {
	result := make([]string, 0, len(metadataMap))
	for ecosystem := range metadataMap {
		result = append(result, ecosystem)
	}
	sort.Strings(result)
	return result
}
