package ecosystem

import "risk-guard/src/ecosystem/def"

func DetectLockfileWithManager(ecoName, manifestDir, repoRoot string) (*string, *string) {
	eco, err := def.Get(ecoName)
	if err != nil {
		return nil, nil
	}
	pm, lockfile := eco.DetectPackageManager(manifestDir, repoRoot)
	if pm == nil {
		return lockfile, nil
	}
	name := pm.Name()
	return lockfile, &name
}
