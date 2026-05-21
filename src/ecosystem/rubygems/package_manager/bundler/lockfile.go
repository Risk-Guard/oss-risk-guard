package bundler

import (
	"risk-guard/src/ecosystem/def"
	"risk-guard/src/ecosystem/lockfile"
	"risk-guard/src/models"
)

const LockfileName = "Gemfile.lock"

var Manager = def.NewPackageManager("bundler", "rubygems", LockfileName)

func DetectLockfile(manifestDir, repoRoot string) *string {
	return lockfile.Detect(manifestDir, repoRoot, LockfileName)
}

func OwnsLockfile(filename string) bool {
	return filename == LockfileName
}

func ParseLockfile(_ []byte) ([]models.DepsTreeEdge, error) {
	return nil, nil
}
