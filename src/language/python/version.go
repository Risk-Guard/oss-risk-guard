package python

import (
	"fmt"

	pep440 "github.com/aquasecurity/go-pep440-version"
)

func (p *Python) CompareVersions(a, b string) (int, error) {
	va, err := pep440.Parse(a)
	if err != nil {
		return 0, fmt.Errorf("invalid PEP 440 version %q: %w", a, err)
	}
	vb, err := pep440.Parse(b)
	if err != nil {
		return 0, fmt.Errorf("invalid PEP 440 version %q: %w", b, err)
	}
	return va.Compare(vb), nil
}
