package common

import (
	"testing"
	"time"
)

func TestParseRegistryTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Time
		wantErr bool
	}{
		{
			name:  "RFC3339 no fractional seconds",
			input: "2024-01-15T10:30:37Z",
			want:  time.Date(2024, 1, 15, 10, 30, 37, 0, time.UTC),
		},
		{
			name:  "RFC3339 with milliseconds",
			input: "2024-01-15T10:30:37.019Z",
			want:  time.Date(2024, 1, 15, 10, 30, 37, 19_000_000, time.UTC),
		},
		{
			name:  "RFC3339 with microseconds",
			input: "2024-01-15T10:30:37.019123Z",
			want:  time.Date(2024, 1, 15, 10, 30, 37, 19_123_000, time.UTC),
		},
		{
			name:  "RFC3339 with nanoseconds",
			input: "2024-01-15T10:30:37.019123456Z",
			want:  time.Date(2024, 1, 15, 10, 30, 37, 19_123_456, time.UTC),
		},
		{
			name:  "RFC3339 with timezone offset",
			input: "2024-01-15T10:30:37+05:00",
			want:  time.Date(2024, 1, 15, 10, 30, 37, 0, time.FixedZone("", 5*60*60)),
		},
		{
			name:  "RFC3339 fractional with timezone offset",
			input: "2024-01-15T10:30:37.500+05:00",
			want:  time.Date(2024, 1, 15, 10, 30, 37, 500_000_000, time.FixedZone("", 5*60*60)),
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "garbage input",
			input:   "not-a-timestamp",
			wantErr: true,
		},
		{
			name:    "date only",
			input:   "2024-01-15",
			wantErr: true,
		},
		{
			name:    "PyPI format without timezone",
			input:   "2024-01-15T10:30:37",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRegistryTimestamp(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRegistryTimestamp(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !got.Equal(tt.want) {
				t.Errorf("ParseRegistryTimestamp(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
