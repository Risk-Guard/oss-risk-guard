package rubygems

import (
	"risk-guard/src/ecosystem/rubygems/package_manager/bundler"
)

func DetectLockfile(manifestDir, repoRoot string) *string {
	return bundler.DetectLockfile(manifestDir, repoRoot)
}
