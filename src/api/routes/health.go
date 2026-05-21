package routes

import "risk-guard/src/api/route"

type HealthCheckResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

var RouteHealth = route.Route[route.NoParams, route.NoQuery, HealthCheckResponse]{
	Method:      "GET",
	Path:        "/health/check",
	OperationID: "healthCheck",
	Summary:     "Health check",
	Description: "Verifies cache backend connectivity by performing write-then-read test. Returns 503 if backend is unavailable.",
	Tags:        []string{"health"},
}
