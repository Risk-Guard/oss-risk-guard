package policy

func Resolve(policyOverride, repoPolicy, policyDefault *CompiledPolicy) *CompiledPolicy {
	if policyOverride != nil {
		return policyOverride
	}

	base := policyDefault
	if base == nil {
		base = defaultPolicyClone()
	}

	if repoPolicy != nil {
		return merge(base, repoPolicy)
	}

	return base
}
