package pypi

import (
	"risk-guard/src/ecosystem/lockfile"
	"risk-guard/src/ecosystem/pypi/package_manager/pdm"
	"risk-guard/src/ecosystem/pypi/package_manager/pipenv"
	"risk-guard/src/ecosystem/pypi/package_manager/poetry"
	"risk-guard/src/ecosystem/pypi/package_manager/uv"
)

func DetectLockfileWithManager(manifestDir, repoRoot string) (*string, *string) {
	return lockfile.ChooseClosestWithManager(manifestDir, repoRoot, []lockfile.DetectorWithManager{
		{Detect: uv.DetectLockfile, Manager: "uv"},
		{Detect: poetry.DetectLockfile, Manager: "poetry"},
		{Detect: pipenv.DetectLockfile, Manager: "pipenv"},
		{Detect: pdm.DetectLockfile, Manager: "pdm"},
	})
}
