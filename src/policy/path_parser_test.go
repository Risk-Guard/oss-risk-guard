package policy

import (
	"testing"
)

func TestParseSeverityPath_Category(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
		check   func(*SeverityPath) bool
	}{
		{
			path: "category/critical",
			check: func(p *SeverityPath) bool {
				return p.Ecosystem == nil && p.DepthRange == nil &&
					p.Target.IsCategory && p.Target.Name == "critical"
			},
		},
		{
			path: "category/license-compliance",
			check: func(p *SeverityPath) bool {
				return p.Target.IsCategory && p.Target.Name == "license-compliance"
			},
		},
		{
			path: "category/any-name",
			check: func(p *SeverityPath) bool {
				return p.Target.IsCategory && p.Target.Name == "any-name"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := ParseSeverityPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSeverityPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !tt.check(got) {
				t.Errorf("ParseSeverityPath(%q) = %+v, check failed", tt.path, got)
			}
		})
	}
}

func TestParseSeverityPath_Check(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
		check   func(*SeverityPath) bool
	}{
		{
			path: "check/PACKAGE_INSTALL_SCRIPTS",
			check: func(p *SeverityPath) bool {
				return !p.Target.IsCategory && p.Target.Name == "PACKAGE_INSTALL_SCRIPTS"
			},
		},
		{
			path: "check/VULN_RECENT_FREQUENCY",
			check: func(p *SeverityPath) bool {
				return !p.Target.IsCategory && p.Target.Name == "VULN_RECENT_FREQUENCY"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := ParseSeverityPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSeverityPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !tt.check(got) {
				t.Errorf("ParseSeverityPath(%q) = %+v, check failed", tt.path, got)
			}
		})
	}
}

func TestParseSeverityPath_Depth(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
		check   func(*SeverityPath) bool
	}{
		{
			path: "depth/2+/category/critical",
			check: func(p *SeverityPath) bool {
				return p.DepthRange != nil && p.DepthRange.Min == 2 && p.DepthRange.Max == -1
			},
		},
		{
			path: "depth/0/category/critical",
			check: func(p *SeverityPath) bool {
				return p.DepthRange != nil && p.DepthRange.Min == 0 && p.DepthRange.Max == 0
			},
		},
		{
			path: "depth/1-3/category/critical",
			check: func(p *SeverityPath) bool {
				return p.DepthRange != nil && p.DepthRange.Min == 1 && p.DepthRange.Max == 3
			},
		},
		{
			path:    "depth/abc/category/critical",
			wantErr: true,
		},
		{
			path:    "depth/3-1/category/critical", // max < min
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := ParseSeverityPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSeverityPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !tt.check(got) {
				t.Errorf("ParseSeverityPath(%q) = %+v, check failed", tt.path, got)
			}
		})
	}
}

func TestParseSeverityPath_Ecosystem(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
		check   func(*SeverityPath) bool
	}{
		{
			path: "ecosystem/npm/category/critical",
			check: func(p *SeverityPath) bool {
				return p.Ecosystem != nil && *p.Ecosystem == "npm"
			},
		},
		{
			path: "ecosystem/pypi/check/PACKAGE_STALE_RELEASE",
			check: func(p *SeverityPath) bool {
				return p.Ecosystem != nil && *p.Ecosystem == "pypi" &&
					!p.Target.IsCategory && p.Target.Name == "PACKAGE_STALE_RELEASE"
			},
		},
		{
			path: "ecosystem/any-ecosystem/category/critical",
			check: func(p *SeverityPath) bool {
				return p.Ecosystem != nil && *p.Ecosystem == "any-ecosystem"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := ParseSeverityPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSeverityPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !tt.check(got) {
				t.Errorf("ParseSeverityPath(%q) = %+v, check failed", tt.path, got)
			}
		})
	}
}

func TestParseSeverityPath_Combined(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
		check   func(*SeverityPath) bool
	}{
		{
			path: "ecosystem/npm/depth/2+/category/license-compliance",
			check: func(p *SeverityPath) bool {
				return p.Ecosystem != nil && *p.Ecosystem == "npm" &&
					p.DepthRange != nil && p.DepthRange.Min == 2 && p.DepthRange.Max == -1 &&
					p.Target.IsCategory && p.Target.Name == "license-compliance"
			},
		},
		{
			path: "ecosystem/pypi/depth/1/check/PACKAGE_ACTIVE_MALWARE",
			check: func(p *SeverityPath) bool {
				return p.Ecosystem != nil && *p.Ecosystem == "pypi" &&
					p.DepthRange != nil && p.DepthRange.Min == 1 && p.DepthRange.Max == 1 &&
					!p.Target.IsCategory && p.Target.Name == "PACKAGE_ACTIVE_MALWARE"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := ParseSeverityPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSeverityPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !tt.check(got) {
				t.Errorf("ParseSeverityPath(%q) = %+v, check failed", tt.path, got)
			}
		})
	}
}

func TestParseSeverityPath_EnvBasic(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
		check   func(*SeverityPath) bool
	}{
		{
			path: "env/dev/category/critical",
			check: func(p *SeverityPath) bool {
				return p.Env != nil && *p.Env && p.Target.IsCategory && p.Target.Name == "critical"
			},
		},
		{
			path: "env/prod/category/critical",
			check: func(p *SeverityPath) bool {
				return p.Env != nil && !*p.Env && p.Target.IsCategory && p.Target.Name == "critical"
			},
		},
		{
			path: "env/dev/check/VULN_CHECK",
			check: func(p *SeverityPath) bool {
				return p.Env != nil && *p.Env && !p.Target.IsCategory && p.Target.Name == "VULN_CHECK"
			},
		},
		{
			path: "env/prod/check/VULN_CHECK",
			check: func(p *SeverityPath) bool {
				return p.Env != nil && !*p.Env && !p.Target.IsCategory && p.Target.Name == "VULN_CHECK"
			},
		},
		{path: "env/staging/category/critical", wantErr: true},
		{path: "env/category/critical", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := ParseSeverityPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSeverityPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !tt.check(got) {
				t.Errorf("ParseSeverityPath(%q) = %+v, check failed", tt.path, got)
			}
		})
	}
}

func TestParseSeverityPath_EnvCombined(t *testing.T) {
	tests := []struct {
		path  string
		check func(*SeverityPath) bool
	}{
		{
			path: "ecosystem/npm/depth/2+/env/dev/category/critical",
			check: func(p *SeverityPath) bool {
				return p.Ecosystem != nil && *p.Ecosystem == "npm" &&
					p.DepthRange != nil && p.DepthRange.Min == 2 &&
					p.Env != nil && *p.Env && p.Target.IsCategory
			},
		},
		{
			path: "depth/1/env/prod/check/SOURCE_NO_LICENSE",
			check: func(p *SeverityPath) bool {
				return p.DepthRange != nil && p.DepthRange.Min == 1 &&
					p.Env != nil && !*p.Env && !p.Target.IsCategory
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := ParseSeverityPath(tt.path)
			if err != nil {
				t.Errorf("ParseSeverityPath(%q) error = %v", tt.path, err)
				return
			}
			if !tt.check(got) {
				t.Errorf("ParseSeverityPath(%q) = %+v, check failed", tt.path, got)
			}
		})
	}
}

func TestParseSeverityPath_Invalid(t *testing.T) {
	invalidPaths := []string{
		"",
		"category",
		"check",
		"foo/bar",
		"category/critical/extra",
		"depth/2+",
		"ecosystem/npm",
	}

	for _, path := range invalidPaths {
		testName := path
		if testName == "" {
			testName = "<empty>"
		}
		t.Run(testName, func(t *testing.T) {
			_, err := ParseSeverityPath(path)
			if err == nil {
				t.Errorf("ParseSeverityPath(%q) expected error, got nil", path)
			}
		})
	}
}

func TestParseExpectedFailurePath(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
	}{
		{path: "package/npm/lodash", wantErr: false},
		{path: "package/npm/@angular/core", wantErr: false},
		{path: "package/pypi/requests", wantErr: false},
		{path: "source/github.com/org/repo", wantErr: false},
		{path: "root", wantErr: false},
		{path: "package/npm/pkg?version=1.2.3", wantErr: false},
		{path: "npm/lodash", wantErr: true},
		{path: "npm", wantErr: true},
		{path: "package/npm", wantErr: true},
		{path: "unknown/pkg/CHECK", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			err := ParseExpectedFailurePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseExpectedFailurePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestDepthRange_Contains(t *testing.T) {
	tests := []struct {
		name  string
		dr    DepthRange
		depth int
		want  bool
	}{
		{"exact match", DepthRange{Min: 2, Max: 2}, 2, true},
		{"exact no match low", DepthRange{Min: 2, Max: 2}, 1, false},
		{"exact no match high", DepthRange{Min: 2, Max: 2}, 3, false},
		{"open ended match", DepthRange{Min: 2, Max: -1}, 5, true},
		{"open ended match boundary", DepthRange{Min: 2, Max: -1}, 2, true},
		{"open ended no match", DepthRange{Min: 2, Max: -1}, 1, false},
		{"range match low", DepthRange{Min: 1, Max: 3}, 1, true},
		{"range match mid", DepthRange{Min: 1, Max: 3}, 2, true},
		{"range match high", DepthRange{Min: 1, Max: 3}, 3, true},
		{"range no match low", DepthRange{Min: 1, Max: 3}, 0, false},
		{"range no match high", DepthRange{Min: 1, Max: 3}, 4, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.dr.Contains(tt.depth); got != tt.want {
				t.Errorf("DepthRange{%d,%d}.Contains(%d) = %v, want %v",
					tt.dr.Min, tt.dr.Max, tt.depth, got, tt.want)
			}
		})
	}
}

func TestComputeSpecificity(t *testing.T) {
	eco := "npm"
	src := "github.com/org/repo"
	tests := []struct {
		name string
		path SeverityPath
		want int
	}{
		{
			name: "category only",
			path: SeverityPath{Target: PathTarget{IsCategory: true, Name: "critical"}},
			want: 0,
		},
		{
			name: "check only",
			path: SeverityPath{Target: PathTarget{IsCategory: false, Name: "CHECK"}},
			want: 1,
		},
		{
			name: "ecosystem + category",
			path: SeverityPath{Ecosystem: &eco, Target: PathTarget{IsCategory: true}},
			want: 1,
		},
		{
			name: "depth + category",
			path: SeverityPath{DepthRange: &DepthRange{Min: 2, Max: -1}, Target: PathTarget{IsCategory: true}},
			want: 1,
		},
		{
			name: "ecosystem + depth + check",
			path: SeverityPath{
				Ecosystem:  &eco,
				DepthRange: &DepthRange{Min: 2, Max: -1},
				Target:     PathTarget{IsCategory: false, Name: "CHECK"},
			},
			want: 3,
		},
		{
			name: "source path + category",
			path: SeverityPath{SourcePath: &src, Target: PathTarget{IsCategory: true}},
			want: 2,
		},
		{
			name: "source path + check",
			path: SeverityPath{SourcePath: &src, Target: PathTarget{IsCategory: false, Name: "CHECK"}},
			want: 3,
		},
		{
			name: "env + category",
			path: SeverityPath{Env: boolPtr(true), Target: PathTarget{IsCategory: true, Name: "critical"}},
			want: 1,
		},
		{
			name: "ecosystem + env + category",
			path: SeverityPath{Ecosystem: &eco, Env: boolPtr(true), Target: PathTarget{IsCategory: true, Name: "critical"}},
			want: 2,
		},
		{
			name: "ecosystem + depth + env + check",
			path: SeverityPath{
				Ecosystem:  &eco,
				DepthRange: &DepthRange{Min: 2, Max: -1},
				Env:        boolPtr(false),
				Target:     PathTarget{IsCategory: false, Name: "CHECK"},
			},
			want: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ComputeSpecificity(&tt.path); got != tt.want {
				t.Errorf("ComputeSpecificity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"foo", "foo", true},
		{"foo", "bar", false},
		{"foo*", "foobar", true},
		{"foo*", "foo", true},
		{"foo*", "barfoo", false},
		{"*bar", "foobar", true},
		{"*bar", "bar", true},
		{"*bar", "barfoo", false},
		{"foo*bar", "fooXXXbar", true},
		{"foo*bar", "foobar", true},
		{"foo*bar", "foobarbaz", false},
		{"*", "anything", true},
		{"*", "", true},
		{"SOURCE_*", "SOURCE_NO_LICENSE", true},
		{"SOURCE_*", "PACKAGE_NO_LICENSE", false},
		{"github.com/org/*", "github.com/org/repo", true},
		{"github.com/org/*", "github.com/other/repo", false},
		{"github.com/*/*", "github.com/org/repo", true},
		{"github.com/*", "github.com/org/repo", false},
		{"github.com/*", "github.com/org", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.value, func(t *testing.T) {
			if got := MatchesPattern(tt.pattern, tt.value); got != tt.want {
				t.Errorf("MatchesPattern(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestParseSeverityPath_Source(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
		check   func(*SeverityPath) bool
	}{
		{
			path: `source/"github.com/org/repo"/category/critical`,
			check: func(p *SeverityPath) bool {
				return p.SourcePath != nil && *p.SourcePath == "github.com/org/repo" &&
					p.Target.IsCategory && p.Target.Name == "critical"
			},
		},
		{
			path: `source/"github.com/org/*"/check/SOURCE_NO_LICENSE`,
			check: func(p *SeverityPath) bool {
				return p.SourcePath != nil && *p.SourcePath == "github.com/org/*" &&
					!p.Target.IsCategory && p.Target.Name == "SOURCE_NO_LICENSE"
			},
		},
		{
			path: `source/"github.com/*"/category/critical`,
			check: func(p *SeverityPath) bool {
				return p.SourcePath != nil && *p.SourcePath == "github.com/*" &&
					p.Target.IsCategory && p.Target.Name == "critical"
			},
		},
		{
			path: `source/"github.com/category/repo"/check/FOO`,
			check: func(p *SeverityPath) bool {
				return p.SourcePath != nil && *p.SourcePath == "github.com/category/repo" &&
					!p.Target.IsCategory && p.Target.Name == "FOO"
			},
		},
		{
			path:    "source/github.com/org/repo/category/critical",
			wantErr: true,
		},
		{
			path:    `source/""/category/critical`,
			wantErr: true,
		},
		{
			path:    `source/"unclosed/category/critical`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := ParseSeverityPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSeverityPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !tt.check(got) {
				t.Errorf("ParseSeverityPath(%q) = %+v, check failed", tt.path, got)
			}
		})
	}
}

func boolPtr(v bool) *bool {
	return &v
}
