package executiondag

type Status string

const (
	// StatusSuccess indicates the node executed successfully
	StatusSuccess Status = "success"

	// StatusSkipped indicates the node was skipped
	StatusSkipped Status = "skipped"
)

func (s Status) String() string {
	return string(s)
}
