package ecosystem

import (
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"
	npmeco "github.com/Risk-Guard/oss-risk-guard/src/ecosystem/npm"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/pypi"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/rubygems"
)

func init() {
	def.RegisterEcosystem(npmeco.Ecosystem())
	def.RegisterEcosystem(pypi.Ecosystem())
	def.RegisterEcosystem(rubygems.Ecosystem())
}
