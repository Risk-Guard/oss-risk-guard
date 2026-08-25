package pep508

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExactPin(t *testing.T) {
	tests := []struct {
		name       string
		specifiers []string
		want       string
	}{
		{name: "exact pin", specifiers: []string{"==22.0.0"}, want: "22.0.0"},
		{name: "arbitrary equality", specifiers: []string{"===22.0.0"}, want: "22.0.0"},
		{name: "pin with pre-release", specifiers: []string{"==1.0a1"}, want: "1.0a1"},
		{name: "pin with local version", specifiers: []string{"==1.0+local"}, want: "1.0+local"},
		{name: "pin with epoch", specifiers: []string{"==1!1.0"}, want: "1!1.0"},
		{name: "leading v normalized away", specifiers: []string{"==v1.0"}, want: "1.0"},
		{name: "leading V normalized away", specifiers: []string{"==V1.0"}, want: "1.0"},
		{name: "arbitrary equality keeps leading v", specifiers: []string{"===v1.0"}, want: "v1.0"},

		{name: "no specifiers", specifiers: []string{}, want: ""},
		{name: "wildcard is a prefix match", specifiers: []string{"==1.*"}, want: ""},
		{name: "greater than or equal", specifiers: []string{">=1.0"}, want: ""},
		{name: "compatible release", specifiers: []string{"~=1.4.2"}, want: ""},
		{name: "not equal", specifiers: []string{"!=1.0"}, want: ""},
		{name: "range", specifiers: []string{">=1.0", "<2.0"}, want: ""},

		{name: "pin alongside a looser bound", specifiers: []string{">=20", "==22.0.0"}, want: "22.0.0"},
		{name: "pin alongside an exclusion", specifiers: []string{"==22.0.0", "!=21.0.0"}, want: "22.0.0"},
		{name: "repeated identical pins", specifiers: []string{"==22.0.0", "==22.0.0"}, want: "22.0.0"},
		{name: "conflicting pins are unsatisfiable", specifiers: []string{"==22.0.0", "==23.0.0"}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ExactPin(tt.specifiers))
		})
	}
}
