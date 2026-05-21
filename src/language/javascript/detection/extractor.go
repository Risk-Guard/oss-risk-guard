package detection

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

var packageJSONInstallScriptKeys = []string{
	"preinstall",  // runs BEFORE the package is installed
	"install",     // runs DURING the package install
	"postinstall", // runs AFTER the package is installed

	// Maybe add these later
	// "prepare",     // runs on local npm install and when installing git dependencies
	// "prepublish",  // deprecated but still runs on local npm install
}

// ExtractInstallScriptsFromPackageJSON extracts install scripts from a package.json file path.
func ExtractInstallScriptsFromPackageJSON(path string) ([]string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from controlled file walk
	if err != nil {
		return nil, fmt.Errorf("failed to read package.json: %w", err)
	}
	return ExtractInstallScriptsFromContent(data)
}

// ExtractInstallScriptsFromContent extracts install scripts from package.json content.
func ExtractInstallScriptsFromContent(data []byte) ([]string, error) {
	var pkg struct {
		Name    string            `json:"name"`
		Scripts map[string]string `json:"scripts"`
	}

	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	var scripts []string
	for _, scriptName := range packageJSONInstallScriptKeys {
		if _, exists := pkg.Scripts[scriptName]; exists {
			scripts = append(scripts, scriptName)
		}
	}
	sort.Strings(scripts)

	return scripts, nil
}
