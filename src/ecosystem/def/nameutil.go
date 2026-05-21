package def

import "risk-guard/src/models"

type NameProvider interface {
	GetName() *string
	GetIsDynamic() bool
	GetDynamicReason() string
}

func ApplyNameResult(result *models.ManifestResult, nr NameProvider) {
	if result.Name == nil {
		result.Name = nr.GetName()
	}
	if nr.GetIsDynamic() {
		result.IsDynamic = true
		if reason := nr.GetDynamicReason(); reason != "" {
			result.DynamicReason = &reason
		}
	}
}
