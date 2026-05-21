package rubygems

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchPackageVersionWithMetadata_Success(t *testing.T) {
	mockResponse := RubyGemsV2VersionResponse{
		Name:          "rails",
		Version:       "7.0.4",
		Authors:       "David Heinemeier Hansson",
		Info:          "Full-stack web framework",
		Licenses:      []string{"MIT"},
		SourceCodeURI: "https://github.com/rails/rails",
		HomepageURI:   "https://rubyonrails.org",
		CreatedAt:     "2022-12-01T00:00:00Z",
		Dependencies: Dependencies{
			Runtime: []APIDependency{
				{Name: "actionpack", Requirements: "= 7.0.4"},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(mockResponse); err != nil {
			t.Errorf("Failed to encode JSON response: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)
	resp, metadata, err := client.FetchPackageVersionWithMetadata("rails", "7.0.4")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if metadata.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", metadata.StatusCode)
	}

	if resp == nil {
		t.Fatal("Expected response, got nil")
		return
	}

	if resp.Name != "rails" {
		t.Errorf("Expected name 'rails', got '%s'", resp.Name)
	}

	if resp.CreatedAt != "2022-12-01T00:00:00Z" {
		t.Errorf("Expected created_at '2022-12-01T00:00:00Z', got '%s'", resp.CreatedAt)
	}
}

func TestFetchPackageVersionWithMetadata_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		if _, err := w.Write([]byte(`{"error": "Not Found"}`)); err != nil {
			t.Errorf("Failed to write response body: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)
	resp, metadata, err := client.FetchPackageVersionWithMetadata("nonexistent", "1.0.0")
	if err != nil {
		t.Fatalf("Expected no error for metadata capture, got %v", err)
	}

	if metadata.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", metadata.StatusCode)
	}

	if resp != nil {
		t.Error("Expected nil response for 404, got non-nil")
	}
}

func TestFetchPackageVersionWithMetadata_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"invalid json`)); err != nil {
			t.Errorf("Failed to write response body: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)
	_, _, err := client.FetchPackageVersionWithMetadata("rails", "7.0.4")
	if err == nil {
		t.Error("Expected JSON decode error, got nil")
	}
}

func TestFetchPackageVersionWithMetadata_HTTPErrors(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		responseBody  string
		expectedInErr []string
	}{
		{
			name:          "server error 500",
			statusCode:    http.StatusInternalServerError,
			responseBody:  `{"error": "Database connection failed"}`,
			expectedInErr: []string{"500", "Database connection"},
		},
		{
			name:          "service unavailable 503",
			statusCode:    http.StatusServiceUnavailable,
			responseBody:  `{"error": "Service temporarily unavailable"}`,
			expectedInErr: []string{"503"},
		},
		{
			name:          "unauthorized 401",
			statusCode:    http.StatusUnauthorized,
			responseBody:  `{"error": "Authentication required"}`,
			expectedInErr: []string{"401", "client error"},
		},
		{
			name:          "forbidden 403",
			statusCode:    http.StatusForbidden,
			responseBody:  `{"error": "Access denied"}`,
			expectedInErr: []string{"403"},
		},
		{
			name:          "rate limited 429",
			statusCode:    http.StatusTooManyRequests,
			responseBody:  `{"error": "Rate limit exceeded"}`,
			expectedInErr: []string{"429"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if _, err := w.Write([]byte(tt.responseBody)); err != nil {
					t.Errorf("Failed to write response body: %v", err)
				}
			}))
			defer server.Close()

			client := NewClient(server.URL)
			resp, metadata, err := client.FetchPackageVersionWithMetadata("test-gem", "1.0.0")

			if err == nil {
				t.Fatalf("Expected error for %d response, got nil", tt.statusCode)
			}
			for _, expected := range tt.expectedInErr {
				if !strings.Contains(err.Error(), expected) {
					t.Errorf("Error should contain %q, got: %v", expected, err)
				}
			}

			if resp != nil {
				t.Error("Expected nil response for error status")
			}
			if metadata != nil {
				t.Error("Expected nil metadata for error status")
			}
		})
	}
}
