package category

type RiskCategory string

const (
	RiskCategoryCritical              RiskCategory = "critical"
	RiskCategoryTitleAssurance        RiskCategory = "title-assurance"
	RiskCategoryLicenseCompliance     RiskCategory = "license-compliance"
	RiskCategoryContinuityAssurance   RiskCategory = "continuity-assurance"
	RiskCategorySecurityVulnerability RiskCategory = "security-vulnerability"
)
