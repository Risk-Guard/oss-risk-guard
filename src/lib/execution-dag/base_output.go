package executiondag

// BaseOutput provides default implementation of StatusProvider interface.
// Embed this in your output types to avoid boilerplate.
type BaseOutput struct {
	Status       Status `json:"status,omitempty"`
	StatusReason string `json:"status_reason,omitempty"`
}

func (b BaseOutput) GetStatus() Status {
	return b.Status
}

func (b BaseOutput) GetStatusReason() string {
	return b.StatusReason
}
