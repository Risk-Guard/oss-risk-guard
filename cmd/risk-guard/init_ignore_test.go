package main

import (
	"reflect"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

func TestIgnorableDirsFromManifests(t *testing.T) {
	cases := []struct {
		name      string
		manifests []models.DetectedManifest
		want      []string
	}{
		{
			name:      "empty",
			manifests: nil,
			want:      nil,
		},
		{
			name: "root manifest excluded",
			manifests: []models.DetectedManifest{
				{Paths: []string{"requirements.txt"}},
			},
			want: nil,
		},
		{
			name: "collapsed to top-level and sorted",
			manifests: []models.DetectedManifest{
				{Paths: []string{"vendor/x/setup.py"}},
				{Paths: []string{"third_party/foo/package.json"}},
				{Paths: []string{"benchmarks/dynamo/genai_layers/requirements.txt"}},
				{Paths: []string{"benchmarks/operator_benchmark/pt_extension/setup.py"}}, // same top-level
			},
			want: []string{"benchmarks", "third_party", "vendor"},
		},
		{
			name: "deduped across manifests and grouped paths",
			manifests: []models.DetectedManifest{
				{Paths: []string{"third_party/pyproject.toml", "third_party/setup.py"}},
				{Paths: []string{"third_party/sub/Gemfile"}},
				{Paths: []string{"requirements.txt"}}, // root, excluded
			},
			want: []string{"third_party"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ignorableDirsFromManifests(c.manifests)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("ignorableDirsFromManifests = %v, want %v", got, c.want)
			}
		})
	}
}
