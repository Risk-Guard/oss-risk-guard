package javascript

import (
	"fmt"
	"risk-guard/src/common"
	"risk-guard/src/models"
	"sort"
	"strings"
	"time"

	npmregistry "risk-guard/src/registry/npm"
)

// extractMaintainersWithPublishHistory merges npm's top-level maintainers list
// with per-version _npmUser data into a single Maintainer slice.
func (j *JavaScript) extractMaintainersWithPublishHistory(versions map[string]npmregistry.NPMVersionDetails, timeMap map[string]string, currentMaintainers []npmregistry.NPMMaintainer) ([]models.Maintainer, error) {
	type accum struct {
		name                string
		email               string
		firstPublishVersion string
		firstPublishDate    time.Time
		lastPublishVersion  string
		lastPublishDate     time.Time
		versionCount        int
	}

	byName := make(map[string]*accum)

	for version, details := range versions {
		if details.NpmUser == nil || details.NpmUser.Name == "" {
			continue
		}

		dateStr, ok := timeMap[version]
		if !ok || dateStr == "" {
			continue
		}
		publishDate, err := common.ParseRegistryTimestamp(dateStr)
		if err != nil {
			return nil, fmt.Errorf("parsing publish date for version %s: %w", version, err)
		}

		key := strings.ToLower(details.NpmUser.Name)
		acc, exists := byName[key]
		if !exists {
			acc = &accum{
				name:                details.NpmUser.Name,
				email:               details.NpmUser.Email,
				firstPublishVersion: version,
				firstPublishDate:    publishDate,
				lastPublishVersion:  version,
				lastPublishDate:     publishDate,
			}
			byName[key] = acc
		}

		acc.versionCount++

		if publishDate.Before(acc.firstPublishDate) {
			acc.firstPublishDate = publishDate
			acc.firstPublishVersion = version
		}
		if publishDate.After(acc.lastPublishDate) {
			acc.lastPublishDate = publishDate
			acc.lastPublishVersion = version
		}

		if details.NpmUser.Email != "" {
			acc.email = details.NpmUser.Email
		}
	}

	activeMaintainers := make(map[string]bool, len(currentMaintainers))
	for _, m := range currentMaintainers {
		activeMaintainers[strings.ToLower(m.Name)] = true
	}

	// Build merged list: start from publisher history, then add any
	// current maintainers who never published a version.
	result := make([]models.Maintainer, 0, len(byName)+len(currentMaintainers))
	seen := make(map[string]bool, len(byName))

	for key, acc := range byName {
		seen[key] = true
		isActive := activeMaintainers[key]
		result = append(result, models.Maintainer{
			Name:                acc.name,
			Email:               acc.email,
			Role:                "maintainer",
			FirstPublishVersion: &acc.firstPublishVersion,
			FirstPublishDate:    &acc.firstPublishDate,
			LastPublishVersion:  &acc.lastPublishVersion,
			LastPublishDate:     &acc.lastPublishDate,
			VersionCount:        acc.versionCount,
			IsActive:            &isActive,
		})
	}

	for _, m := range currentMaintainers {
		key := strings.ToLower(m.Name)
		if seen[key] {
			continue
		}
		isActive := true
		result = append(result, models.Maintainer{
			Name:     m.Name,
			Email:    m.Email,
			Role:     "maintainer",
			IsActive: &isActive,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		// Maintainers with publish history sort by first publish date.
		// Maintainers without publish history sort to the end.
		iHas := result[i].FirstPublishDate != nil
		jHas := result[j].FirstPublishDate != nil
		if iHas != jHas {
			return iHas
		}
		if iHas && jHas {
			return result[i].FirstPublishDate.Before(*result[j].FirstPublishDate)
		}
		return result[i].Name < result[j].Name
	})

	return result, nil
}
