package rubygems

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/pathutil"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

var gemspecDirectiveRegex = regexp.MustCompile(`(?m)^\s*gemspec\b`)

func DetectManifests(rootDir string) ([]models.DetectedManifest, error) {
	var manifests []models.DetectedManifest
	skipDirs := pathutil.MergeSkipDirsWithCommonNonSourceDirs(Definition.SkipDirectories)

	err := pathutil.WalkDirs(rootDir, skipDirs, func(dir string, _ []fs.DirEntry) error {
		dirManifests, err := detectManifestsInDir(dir, rootDir)
		if err != nil {
			return err
		}
		manifests = append(manifests, dirManifests...)
		return nil
	})

	return manifests, err
}

func detectManifestsInDir(dir, rootDir string) ([]models.DetectedManifest, error) {
	gemspecs := findGemspecs(dir)
	hasGemfile := fileExists(dir, "Gemfile")

	var gemfileHasDirective bool
	if hasGemfile {
		var err error
		gemfileHasDirective, err = gemfileReferencesGemspec(dir)
		if err != nil {
			return nil, err
		}
	}

	var manifests []models.DetectedManifest
	bundler := "bundler"

	for _, gs := range gemspecs {
		paths := []string{relPath(rootDir, dir, gs)}
		if gemfileHasDirective {
			paths = append(paths, relPath(rootDir, dir, "Gemfile"))
		}
		manifests = append(manifests, models.DetectedManifest{
			Ecosystem:      "rubygems",
			PackageManager: &bundler,
			Paths:          paths,
			Lockfile:       DetectLockfile(dir, rootDir),
		})
	}

	if hasGemfile && (len(gemspecs) == 0 || !gemfileHasDirective) {
		manifests = append(manifests, models.DetectedManifest{
			Ecosystem:      "rubygems",
			PackageManager: &bundler,
			Paths:          []string{relPath(rootDir, dir, "Gemfile")},
			Lockfile:       DetectLockfile(dir, rootDir),
		})
	}

	return manifests, nil
}

func findGemspecs(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var gemspecs []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".gemspec") {
			gemspecs = append(gemspecs, e.Name())
		}
	}
	return gemspecs
}

func gemfileReferencesGemspec(dir string) (bool, error) {
	// #nosec G304 -- path is constructed from filepath.Join with validated directory
	f, err := os.Open(filepath.Join(dir, "Gemfile"))
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		if gemspecDirectiveRegex.MatchString(scanner.Text()) {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func fileExists(dir, filename string) bool {
	_, err := os.Stat(filepath.Join(dir, filename))
	return err == nil
}

func relPath(rootDir, dir, filename string) string {
	full := filepath.Join(dir, filename)
	rel, err := filepath.Rel(rootDir, full)
	if err != nil {
		return filename
	}
	return rel
}
