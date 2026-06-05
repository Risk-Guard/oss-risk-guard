package main

import "testing"

func TestCurrentURLFromMessage(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want string
	}{
		{"evidence block", "Source repository could not be found\n\nEvidence:\n- URL: https://example.com/repo", "https://example.com/repo"},
		{"bare url line", "URL: https://example.com/repo", "https://example.com/repo"},
		{"no url defined", "No source repository is defined\n- No source URL present in package metadata", ""},
		{"no url at all", "nothing here", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := currentURLFromMessage(c.msg); got != c.want {
				t.Errorf("currentURLFromMessage() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestCollectSourceURLFindings(t *testing.T) {
	report := newTestReport(t, []testFinding{
		{Package: "package/pypi/beautifulsoup4", RuleID: "SOURCE_REPO_NOT_FOUND", Level: "error", Message: "Source repository could not be found\n\nEvidence:\n- URL: https://www.crummy.com/bs4/"},
		{Package: "package/pypi/foo", RuleID: "SOURCE_REPO_NOT_FOUND", Level: "error", Message: "No source repository is defined"},
		{Package: "package/npm/lodash", RuleID: "PACKAGE_STALE_RELEASE", Level: "warning", Message: "stale"},
	})

	got := collectSourceURLFindings(report)
	if len(got) != 2 {
		t.Fatalf("expected 2 SOURCE_REPO_NOT_FOUND findings, got %d: %+v", len(got), got)
	}
	if got[0].EntityKey != "package/pypi/beautifulsoup4" || got[0].Current != "https://www.crummy.com/bs4/" {
		t.Errorf("unexpected first finding: %+v", got[0])
	}
	if got[1].EntityKey != "package/pypi/foo" || got[1].Current != "" {
		t.Errorf("unexpected second finding (no-url case): %+v", got[1])
	}
}
