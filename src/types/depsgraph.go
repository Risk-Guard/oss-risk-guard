package types

import "risk-guard/src/models"

type PathInfo struct {
	Path         []string
	RootLocation *models.LocationInfo
	Dev          bool
}
