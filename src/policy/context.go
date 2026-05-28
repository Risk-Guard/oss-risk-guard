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
