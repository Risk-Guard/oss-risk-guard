package python

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
	"github.com/Risk-Guard/oss-risk-guard/src/language/metadata"
	"github.com/Risk-Guard/oss-risk-guard/src/logger"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	"github.com/stretchr/testify/assert"
)

// TestFetchPackageFromRegistry_Quarantined exercises the real fetch path: a quarantined
// project 404s on the detail endpoint but the secondary simple-index lookup surfaces the
// PEP 792 project-status, which must land on RegistryResponse.ProjectStatus.
func TestFetchPackageFromRegistry_Quarantined(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/simple/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"datacamp-light","project-status":{"status":"quarantined"},"files":[],"versions":[]}`))
			return
		}
		// Detail endpoint (/{name}/json) 404s for a quarantined project.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer server.Close()

	log, err := logger.NewLogger("error")
	assert.NoError(t, err)
	ctx := ctxutil.SetLogger(context.Background(), log)

	p := New(&metadata.Metadata{Ecosystem: "pypi", Source: executiondag.Source{URL: server.URL}})

	resp, err := p.FetchPackageFromRegistry(ctx, models.PackageInfo{Ecosystem: "pypi", Name: "datacamp-light"})
	assert.NoError(t, err)
	assert.Equal(t, 404, resp.StatusCode)
	assert.Equal(t, "quarantined", resp.ProjectStatus)
}

func TestExtractExtraMarker(t *testing.T) {
	tests := []struct {
		name   string
		marker string
		want   *string
	}{
		{
			name:   "double quotes",
			marker: `extra == "dev"`,
			want:   ptr("dev"),
		},
		{
			name:   "single quotes",
			marker: `extra == 'test'`,
			want:   ptr("test"),
		},
		{
			name:   "no spaces",
			marker: `extra=="dev"`,
			want:   ptr("dev"),
		},
		{
			name:   "compound with python_version first",
			marker: `python_version >= "3.6" and extra == "dev"`,
			want:   ptr("dev"),
		},
		{
			name:   "compound with sys_platform",
			marker: `sys_platform == "win32" and extra == "dev"`,
			want:   ptr("dev"),
		},
		{
			name:   "no extra marker",
			marker: `python_version >= "3.6"`,
			want:   nil,
		},
		{
			name:   "empty string",
			marker: "",
			want:   nil,
		},
		{
			name:   "i18n extra",
			marker: `extra == "i18n"`,
			want:   ptr("i18n"),
		},
		{
			name:   "mismatched quotes double-single",
			marker: `extra == "dev'`,
			want:   nil,
		},
		{
			name:   "mismatched quotes single-double",
			marker: `extra == 'dev"`,
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractExtraMarker(tt.marker)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				assert.NotNil(t, got)
				assert.Equal(t, *tt.want, *got)
			}
		})
	}
}

func ptr(s string) *string {
	return &s
}
