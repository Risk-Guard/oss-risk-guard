package detection

import (
	"encoding/json"
	"fmt"
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
