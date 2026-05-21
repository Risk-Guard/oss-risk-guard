package route

type Route[Params, Query, Response any] struct {
	Method      string
	Path        string
	OperationID string
	Summary     string
	Description string
	Tags        []string
}

type (
	NoParams struct{}
	NoQuery  struct{}
)
