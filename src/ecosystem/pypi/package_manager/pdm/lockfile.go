package pdm

import (
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/lockfile"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

const LockfileName = "pdm.lock"

var Manager = def.NewPackageManager("pdm", "pypi", LockfileName)

func DetectLockfile(manifestDir, repoRoot string) *string {
	return lockfile.Detect(manifestDir, repoRoot, LockfileName)
}

func OwnsLockfile(filename string) bool {
	return filename == LockfileName
}

func ParseLockfile(_ []byte) ([]models.DepsTreeEdge, error) {
	return nil, nil
}
