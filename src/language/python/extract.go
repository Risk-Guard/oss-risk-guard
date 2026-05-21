package python

import (
	"context"
	"fmt"
	"regexp"
	"risk-guard/src/common"
	"risk-guard/src/ctxutil"
	"risk-guard/src/models"
	"sort"
	"strings"
	"time"

	pypiregistry "risk-guard/src/registry/pypi"

	"go.uber.org/zap"
)

// extractSourceURL extracts and validates the repository URL from project URLs
func (p *Python) extractSourceURL(ctx context.Context, projectURLs map[string]string, packageName string) (*string, *string, *string) {
	log := ctxutil.GetLogger(ctx)

	if len(projectURLs) == 0 {
		return nil, nil, nil
	}

	// Priority list of keys to check (case-insensitive)
	priorities := []string{"code", "repository", "source", "source code", "github", "homepage"}

	for _, priority := range priorities {
		for key, url := range projectURLs {
			if strings.EqualFold(key, priority) {
				normalized, finding, err := common.ValidateAndNormalizeURL(url)
				if err != nil {
					log.Warn("rejecting invalid source URL from pypi package metadata",
						zap.String("package", packageName),
						zap.String("url", url),
						zap.String("normalized", normalized),
						zap.Error(err))
					reason := err.Error()
					return nil, &url, &reason
				}
				if finding != nil {
					return &normalized, &url, finding
				}

				return &normalized, nil, nil
			}
		}
	}

	return nil, nil, nil
}

// extractLicense extracts license information from PyPI info
func (p *Python) extractLicense(info pypiregistry.PyPIInfo) *string {
	// Modern: license_expression (PEP 639)
	if info.LicenseExpression != "" {
		return &info.LicenseExpression
	}

	// Legacy: license field
	if info.License != "" {
		return &info.License
	}

	// Fallback: Extract from classifiers
	for _, classifier := range info.Classifiers {
		if strings.HasPrefix(classifier, "License :: ") {
			parts := strings.Split(classifier, " :: ")
			if len(parts) >= 2 {
				license := strings.Join(parts[1:], " :: ")
				return &license
			}
		}
	}

	return nil
}

var (
	extraMarkerDoubleQuote = regexp.MustCompile(`extra\s*==\s*"([^"]+)"`)
	extraMarkerSingleQuote = regexp.MustCompile(`extra\s*==\s*'([^']+)'`)
)

func extractExtraMarker(marker string) *string {
	if matches := extraMarkerDoubleQuote.FindStringSubmatch(marker); len(matches) >= 2 {
		return &matches[1]
	}
	if matches := extraMarkerSingleQuote.FindStringSubmatch(marker); len(matches) >= 2 {
		return &matches[1]
	}
	return nil
}

func parseRFC5322Contact(name, email string) models.Maintainer {
	name = strings.TrimSpace(name)
	email = strings.TrimSpace(email)
	if email != "" && strings.Contains(email, "<") && strings.Contains(email, ">") {
		ltIdx := strings.LastIndex(email, "<")
		gtIdx := strings.LastIndex(email, ">")
		if ltIdx != -1 && gtIdx > ltIdx {
			extractedEmail := strings.TrimSpace(email[ltIdx+1 : gtIdx])
			extractedName := strings.Trim(strings.TrimSpace(email[:ltIdx]), `"'`)
			if name == "" && extractedName != "" {
				name = extractedName
			}
			email = extractedEmail
		}
	}
	return models.Maintainer{Name: name, Email: email}
}

// extractMaintainers extracts maintainer information from PyPI ownership data (registry accounts)
// with a fallback to self-declared info fields for packages without ownership data.
func (p *Python) extractMaintainers(info pypiregistry.PyPIInfo, ownership *pypiregistry.PyPIOwnership) []models.Maintainer {
	if ownership != nil && len(ownership.Roles) > 0 {
		maintainers := make([]models.Maintainer, 0, len(ownership.Roles))
		isActive := true
		for _, role := range ownership.Roles {
			if role.User == "" {
				continue
			}
			maintainers = append(maintainers, models.Maintainer{
				Name:     role.User,
				Role:     strings.ToLower(role.Role),
				IsActive: &isActive,
			})
		}
		if len(maintainers) > 0 {
			return maintainers
		}
	}

	var maintainers []models.Maintainer

	if info.Author != "" || info.AuthorEmail != "" {
		m := parseRFC5322Contact(info.Author, info.AuthorEmail)
		m.Role = "author"
		if m.Name != "" || m.Email != "" {
			maintainers = append(maintainers, m)
		}
	}

	if info.Maintainer != "" || info.MaintainerEmail != "" {
		m := parseRFC5322Contact(info.Maintainer, info.MaintainerEmail)
		m.Role = "maintainer"
		if m.Name != "" || m.Email != "" {
			maintainers = append(maintainers, m)
		}
	}

	if len(maintainers) == 0 {
		return nil
	}
	return maintainers
}

func (p *Python) strictParsePyPITimestamp(timestamp string) (time.Time, error) {
	formats := []string{"2006-01-02T15:04:05", "2006-01-02T15:04:05.000000"}
	var lastErr error
	for _, format := range formats {
		parsedTime, err := time.Parse(format, timestamp)
		if err == nil {
			return parsedTime.UTC(), nil
		}
		lastErr = err
	}
	return time.Time{}, fmt.Errorf("PyPI API returned unexpected timestamp format '%s' (expected YYYY-MM-DDTHH:MM:SS): %w", timestamp, lastErr)
}

func (p *Python) findReleaseDate(releases map[string][]pypiregistry.Release, version string) (*time.Time, error) {
	versionReleases, ok := releases[version]
	if !ok || len(versionReleases) == 0 {
		return nil, nil
	}
	var earliest *time.Time
	for _, release := range versionReleases {
		if release.UploadTime == "" {
			continue
		}
		parsedTime, err := p.strictParsePyPITimestamp(release.UploadTime)
		if err != nil {
			return nil, fmt.Errorf("parsing release timestamp for version %s: %w", version, err)
		}
		if earliest == nil || parsedTime.Before(*earliest) {
			earliest = &parsedTime
		}
	}
	return earliest, nil
}

// extractVersions extracts version information from PyPI releases map
func (p *Python) extractVersions(releasesMap map[string][]pypiregistry.Release) ([]models.VersionInfo, error) {
	if len(releasesMap) == 0 {
		return nil, fmt.Errorf("no version data in releases map")
	}

	var versions []models.VersionInfo

	for version, releases := range releasesMap {
		if len(releases) == 0 {
			continue
		}

		var earliestTime time.Time
		for _, release := range releases {
			if release.UploadTime == "" {
				continue
			}
			parsedTime, err := p.strictParsePyPITimestamp(release.UploadTime)
			if err != nil {
				return nil, fmt.Errorf("parsing timestamp for version %s: %w", version, err)
			}

			if earliestTime.IsZero() || parsedTime.Before(earliestTime) {
				earliestTime = parsedTime
			}
		}

		if earliestTime.IsZero() {
			continue
		}

		versions = append(versions, models.VersionInfo{
			Version:    version,
			ReleasedAt: earliestTime,
		})
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("no valid versions found")
	}

	sort.Slice(versions, func(i, j int) bool {
		return versions[i].ReleasedAt.After(versions[j].ReleasedAt)
	})

	return versions, nil
}
