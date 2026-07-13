package provenance

import "context"

// FakeVerifier is a test double returning a canned Result/error. Nodes and checks
// are exercised against it so their logic can be tested without live Sigstore
// verification (which requires real signed bundles and the trust root).
type FakeVerifier struct {
	Result Result
	Err    error
}

// Verify returns the canned Result/error, ignoring the request.
func (f FakeVerifier) Verify(_ context.Context, _ Request) (Result, error) {
	return f.Result, f.Err
}
