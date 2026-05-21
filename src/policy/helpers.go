package policy

import (
	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"sort"
	"strings"
)

func stripQuery(s string) string {
	if idx := strings.Index(s, "?"); idx > 0 {
		return s[:idx]
	}
	return s
}

func extractEcosystem(analysisID string) string {
	if rest, found := strings.CutPrefix(analysisID, "package/"); found {
		if idx := strings.Index(rest, "/"); idx > 0 {
			return rest[:idx]
		}
	}
	if strings.HasPrefix(analysisID, "source/") {
		return "source"
	}
	return ""
}

func extractSourcePath(analysisID string) string {
	if !strings.HasPrefix(analysisID, "source/") {
		return ""
	}
	sourcePath := strings.TrimPrefix(analysisID, "source/")
	if idx := strings.Index(sourcePath, "?"); idx > 0 {
		sourcePath = sourcePath[:idx]
	}
	return sourcePath
}

func categoryStrings(cats []category.RiskCategory) []string {
	if len(cats) == 0 {
		return nil
	}
	result := make([]string, len(cats))
	for i, c := range cats {
		result[i] = string(c)
	}
	sort.Strings(result)
	return result
}

func formatAckNote(ack *ExpectedFailureV2) string {
	note := "Acknowledged: " + ack.Reason
	if ack.ApprovedBy != "" {
		note += " (approved by " + ack.ApprovedBy
		if ack.Expires != nil {
			note += ", expires " + ack.Expires.Format("2006-01-02")
		}
		note += ")"
	} else if ack.Expires != nil {
		note += " (expires " + ack.Expires.Format("2006-01-02") + ")"
	}
	return note
}

func formatExpiredNote(ack *ExpectedFailureV2) string {
	note := "Expired acknowledgment: " + ack.Reason
	if ack.Expires != nil {
		note += " (expired " + ack.Expires.Format("2006-01-02")
		if ack.ApprovedBy != "" {
			note += ", was approved by " + ack.ApprovedBy
		}
		note += ")"
	}
	return note
}
