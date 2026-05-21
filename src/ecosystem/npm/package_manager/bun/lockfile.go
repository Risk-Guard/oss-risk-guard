package bun

import (
	"risk-guard/src/ecosystem/def"
	"risk-guard/src/ecosystem/lockfile"
	"risk-guard/src/models"
	"slices"
)

var LockfileNames = []string{"bun.lock", "bun.lockb"}

var Manager = def.NewPackageManager("bun", "npm", LockfileNames...)

func DetectLockfile(manifestDir, repoRoot string) *string {
	return lockfile.Detect(manifestDir, repoRoot, LockfileNames...)
}

func OwnsLockfile(filename string) bool {
	return slices.Contains(LockfileNames, filename)
}

func ParseLockfile(_ []byte) ([]models.DepsTreeEdge, error) {
	return nil, nil
}
