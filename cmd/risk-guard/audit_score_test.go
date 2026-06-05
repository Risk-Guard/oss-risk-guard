package main

import (
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

func TestManifestProvenance(t *testing.T) {
	str := func(s string) *string { return &s }
	num := func(n int) *int { return &n }

	cases := []struct {
		name string
		loc  *models.LocationInfo
		want string
	}{
		{"nil location", nil, ""},
		{"empty file", &models.LocationInfo{File: str("")}, ""},
		{"file only", &models.LocationInfo{File: str("requirements.txt")}, "requirements.txt"},
		{"file and line", &models.LocationInfo{File: str("requirements.txt"), LineNumber: num(7)}, "requirements.txt:7"},
		{"zero line dropped", &models.LocationInfo{File: str("requirements.txt"), LineNumber: num(0)}, "requirements.txt"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := manifestProvenance(c.loc); got != c.want {
				t.Errorf("manifestProvenance() = %q, want %q", got, c.want)
			}
		})
	}
}
