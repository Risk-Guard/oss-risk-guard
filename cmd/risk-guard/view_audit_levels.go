package main

import (
	"fmt"
	"strings"
)

const (
	levelError   = "error"
	levelWarning = "warning"
	levelNote    = "note"
	levelInfo    = "info" // user-facing label for SARIF "none"
)

// normalizeLevel maps SARIF levels (including the bare "none") to the
// user-facing labels used throughout the view: error/warning/note/info.
func normalizeLevel(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case levelError:
		return levelError
	case levelNote:
		return levelNote
	case "none":
		return levelInfo
	case "", levelWarning:
		return levelWarning
	default:
		return levelWarning
	}
}

func normalizeLevelFilter(level string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(level))
	if f == "" {
		return "all", nil
	}
	switch f {
	case "all", levelError, levelWarning, levelNote, levelInfo:
		return f, nil
	case "none":
		return levelInfo, nil
	}
	return "", fmt.Errorf("invalid --level %q (want one of: all, error, warning, note, info)", level)
}

func levelRank(level string) int {
	switch level {
	case levelError:
		return 0
	case levelWarning:
		return 1
	case levelNote:
		return 2
	case levelInfo:
		return 3
	default:
		return 4
	}
}

type levelCounts struct{ Error, Warning, Note, Info int }

func countByLevel(fs []auditFinding) levelCounts {
	var c levelCounts
	for _, f := range fs {
		switch f.Level {
		case levelError:
			c.Error++
		case levelWarning:
			c.Warning++
		case levelNote:
			c.Note++
		case levelInfo:
			c.Info++
		}
	}
	return c
}

func formatCounts(c levelCounts) string {
	parts := make([]string, 0, 4)
	for _, lc := range []struct {
		label string
		n     int
	}{
		{"error", c.Error},
		{"warning", c.Warning},
		{"note", c.Note},
		{"info", c.Info},
	} {
		if lc.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", lc.n, lc.label))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return ": " + strings.Join(parts, ", ")
}
