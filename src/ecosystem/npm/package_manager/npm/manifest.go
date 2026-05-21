package npm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/pathutil"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"strings"
)

type DepsMap map[string]string

func (d *DepsMap) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("[]")) {
		*d = make(map[string]string)
		return nil
	}

	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*d = m
	return nil
}

type FlexBool bool

func (fb *FlexBool) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	switch s {
	case "true", `"true"`:
		*fb = true
	case "false", `"false"`:
		*fb = false
	default:
		return fmt.Errorf("cannot unmarshal %s into bool", s)
	}
	return nil
}

type PackageJSON struct {
	Name            string            `json:"name"`
	Private         FlexBool          `json:"private"`
	Dependencies    DepsMap           `json:"dependencies"`
	DevDependencies DepsMap           `json:"devDependencies"`
	Scripts         map[string]string `json:"scripts"`
}

func FindPackageJSONFiles(root string, skipDirs []string) ([]string, error) {
	var paths []string
	err := pathutil.WalkDirs(root, skipDirs, func(dir string, entries []fs.DirEntry) error {
		for _, e := range entries {
			if e.Name() == "package.json" {
				paths = append(paths, filepath.Join(dir, e.Name()))
			}
		}
		return nil
	})
	return paths, err
}

func ParsePackageJSON(content string, sourceFile string) ([]models.Dependency, *PackageJSON, error) {
	var pkg PackageJSON

	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return nil, nil, err
	}

	var deps []models.Dependency

	for name, constraint := range pkg.Dependencies {
		if name == "" || constraint == "" {
			continue
		}

		deps = append(deps, models.Dependency{
			AnalysisIdentifier: models.MakeSimplePackageAnalysisIdentifier("npm", strings.TrimSpace(name)),
			Specifiers:         []string{constraint},
			Location: &models.LocationInfo{
				File:       &sourceFile,
				LineNumber: findLineNumber(content, name),
			},
		})
	}

	for name, constraint := range pkg.DevDependencies {
		if name == "" || constraint == "" {
			continue
		}
		if _, exists := pkg.Dependencies[name]; exists {
			continue
		}

		deps = append(deps, models.Dependency{
			AnalysisIdentifier: models.MakeSimplePackageAnalysisIdentifier("npm", strings.TrimSpace(name)),
			Specifiers:         []string{constraint},
			Dev:                true,
			Location: &models.LocationInfo{
				File:       &sourceFile,
				LineNumber: findLineNumber(content, name),
			},
		})
	}

	return deps, &pkg, nil
}

var installScriptNames = []string{"preinstall", "install", "postinstall", "prepare"}

func ExtractInstallScripts(pkg PackageJSON) []string {
	var scripts []string
	for _, name := range installScriptNames {
		if _, ok := pkg.Scripts[name]; ok {
			scripts = append(scripts, name)
		}
	}
	return scripts
}

func findLineNumber(content string, packageName string) *int {
	searchStr := "\"" + packageName + "\""
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.Contains(line, searchStr) {
			lineNum := i + 1
			return &lineNum
		}
	}
	return nil
}
