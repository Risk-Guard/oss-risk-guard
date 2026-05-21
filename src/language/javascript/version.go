package javascript

import (
	"fmt"

	npm "github.com/aquasecurity/go-npm-version/pkg"
)

func (j *JavaScript) CompareVersions(a, b string) (int, error) {
	va, err := npm.NewVersion(a)
	if err != nil {
		return 0, fmt.Errorf("invalid npm version %q: %w", a, err)
	}
	vb, err := npm.NewVersion(b)
	if err != nil {
		return 0, fmt.Errorf("invalid npm version %q: %w", b, err)
	}
	return va.Compare(vb), nil
}
