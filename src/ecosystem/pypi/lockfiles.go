package pypi

import (
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/lockfile"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/pypi/package_manager/pdm"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/pypi/package_manager/pipenv"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/pypi/package_manager/poetry"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/pypi/package_manager/uv"
)

func DetectLockfileWithManager(manifestDir, repoRoot string) (*string, *string) {
	return lockfile.ChooseClosestWithManager(manifestDir, repoRoot, []lockfile.DetectorWithManager{
		{Detect: uv.DetectLockfile, Manager: "uv"},
		{Detect: poetry.DetectLockfile, Manager: "poetry"},
		{Detect: pipenv.DetectLockfile, Manager: "pipenv"},
		{Detect: pdm.DetectLockfile, Manager: "pdm"},
	})
}
