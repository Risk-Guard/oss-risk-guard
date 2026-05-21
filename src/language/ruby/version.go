package ruby

import (
	"fmt"

	"github.com/aquasecurity/go-gem-version"
)

func (r *Ruby) CompareVersions(a, b string) (int, error) {
	va, err := gem.NewVersion(a)
	if err != nil {
		return 0, fmt.Errorf("invalid gem version %q: %w", a, err)
	}
	vb, err := gem.NewVersion(b)
	if err != nil {
		return 0, fmt.Errorf("invalid gem version %q: %w", b, err)
	}
	return va.Compare(vb), nil
}
