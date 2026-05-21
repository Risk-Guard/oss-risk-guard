package def

import "risk-guard/src/ecosystem/lockfile"

type BasePackageManager struct {
	name          string
	ecosystem     string
	lockfileNames []string
}

func NewPackageManager(name, ecosystem string, lockfileNames ...string) *BasePackageManager {
	return &BasePackageManager{
		name:          name,
		ecosystem:     ecosystem,
		lockfileNames: append([]string(nil), lockfileNames...),
	}
}

func (pm *BasePackageManager) Name() string {
	return pm.name
}

func (pm *BasePackageManager) Ecosystem() string {
	return pm.ecosystem
}

func (pm *BasePackageManager) LockfileNames() []string {
	return append([]string(nil), pm.lockfileNames...)
}

func (pm *BasePackageManager) DetectLockfile(manifestDir, repoRoot string) *string {
	return lockfile.Detect(manifestDir, repoRoot, pm.lockfileNames...)
}
