package types

import "github.com/Risk-Guard/oss-risk-guard/src/models"

type PathInfo struct {
	Path         []string
	RootLocation *models.LocationInfo
	Dev          bool
}
