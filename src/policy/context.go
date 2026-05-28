package policy

import "context"

// modeOverrideKey carries a CLI-supplied workflow.mode override into the DAG,
// so the in-DAG policy_loader honors `--mode silent` even when the loaded
// .risk-guard.yml says workflow.mode: disabled (and vice versa).
type modeOverrideKey struct{}

func SetWorkflowModeOverride(ctx context.Context, mode WorkflowMode) context.Context {
	if mode == "" {
		return ctx
	}
	return context.WithValue(ctx, modeOverrideKey{}, mode)
}

// GetWorkflowModeOverride returns the override and whether one was set. An
// empty WorkflowMode return with ok=false means callers should fall back to the
// file-derived mode.
func GetWorkflowModeOverride(ctx context.Context) (WorkflowMode, bool) {
	v, ok := ctx.Value(modeOverrideKey{}).(WorkflowMode)
	return v, ok
}

// rootPolicyKey carries the caller's pre-resolved policy into every DAG in a
// run. policy_loader honors it instead of reading .risk-guard.yml from disk,
// which both (a) makes the user's acknowledgments apply to per-package audits
// and (b) prevents a hostile dependency from shipping its own .risk-guard.yml
// to whitelist itself.
type rootPolicyKey struct{}

type rootPolicyValue struct {
	Compiled  *CompiledPolicy
	RawYAML   string
	Overrides map[string][]PolicyOverride
}

func SetRootPolicy(ctx context.Context, p *CompiledPolicy, rawYAML string, overrides map[string][]PolicyOverride) context.Context {
	if p == nil {
		return ctx
	}
	return context.WithValue(ctx, rootPolicyKey{}, rootPolicyValue{Compiled: p, RawYAML: rawYAML, Overrides: overrides})
}

// GetRootPolicy returns the caller-supplied policy. ok=false means no override
// was set and policy_loader should use its existing on-disk logic (gated by
// input.Trusted).
func GetRootPolicy(ctx context.Context) (*CompiledPolicy, string, map[string][]PolicyOverride, bool) {
	v, ok := ctx.Value(rootPolicyKey{}).(rootPolicyValue)
	if !ok {
		return nil, "", nil, false
	}
	return v.Compiled, v.RawYAML, v.Overrides, true
}

// IsValidWorkflowMode reports whether s names one of the three accepted modes.
// LoadFullFromBytes does not enforce this (the field is a typed alias of
// string, so YAML accepts any value); callers that need strict validation —
// the CLI, policy_loader — must check separately.
func IsValidWorkflowMode(s WorkflowMode) bool {
	switch s {
	case WorkflowModeActive, WorkflowModeNoFail, WorkflowModeSilent, WorkflowModeDisabled:
		return true
	}
	return false
}
