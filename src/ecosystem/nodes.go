package ecosystem

import (
	"risk-guard/src/ecosystem/def"
	npmeco "risk-guard/src/ecosystem/npm"
	"risk-guard/src/ecosystem/pypi"
	"risk-guard/src/ecosystem/rubygems"
)

func init() {
	def.RegisterEcosystem(npmeco.Ecosystem())
	def.RegisterEcosystem(pypi.Ecosystem())
	def.RegisterEcosystem(rubygems.Ecosystem())
}
