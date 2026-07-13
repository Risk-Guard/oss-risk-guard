// Package provenance verifies npm/Sigstore build-provenance attestations,
// establishing an unforgeable binding between a published artifact and the
// source repository + commit it was built from. Unlike npm's self-reported
// gitHead, a verified attestation is cryptographically signed and cannot be
// forged by a typosquat.
//
// The Verifier performs full cryptographic verification (signature chain +
// transparency-log inclusion) offline against a pinned trust root, plus a check
// that the attested subject digest matches the registry-reported artifact hash.
// A bare attestation URL is never proof; only a Result with Verified == true is.
package provenance

import "context"

// FailReason enumerates why verification did not yield a trusted repo binding.
// FailNone means the crypto + digest checks passed.
type FailReason string

const (
	// FailNone indicates successful cryptographic + digest verification.
	FailNone FailReason = ""
	// FailNoAttestation indicates the version advertised no attestation to verify.
	FailNoAttestation FailReason = "no-attestation"
	// FailInvalidSignature indicates the bundle failed cryptographic verification
	// (bad signature, untrusted identity, or missing transparency-log inclusion).
	FailInvalidSignature FailReason = "invalid-signature"
	// FailDigestMismatch indicates the attested subject digest did not match the
	// registry-reported artifact hash — the signature is for a different artifact.
	FailDigestMismatch FailReason = "digest-mismatch"
	// FailMalformedBundle indicates a provenance attestation was present but its
	// bundle could not be parsed. This is a soft miss, not a tampering signal, so a
	// registry-side format change cannot mass-flag packages as invalid.
	FailMalformedBundle FailReason = "malformed-bundle"
	// FailRepoMismatch indicates a validly-signed attestation that names a source
	// repository other than the one being analyzed. Set by the consuming node, not
	// the Verifier, since only the node knows the declared repo.
	FailRepoMismatch FailReason = "repo-mismatch"
)

// Result is the outcome of verifying a package version's build provenance. It is
// declared-repo-agnostic: the Verifier reports what the attestation cryptographically
// establishes (which repo/commit it was built from), and leaves the comparison
// against the declared repo to the caller.
type Result struct {
	// Verified is true only when the signature chain, transparency-log inclusion,
	// and subject-digest match all pass. It says nothing about which repo — the
	// caller must still compare SourceRepo against the declared repo.
	Verified bool
	// SourceRepo is the repository the attestation was built from, e.g.
	// "https://github.com/mozilla/pdf.js". Populated whenever the predicate could
	// be read, even on some failures, so callers can disclose what was attested.
	SourceRepo string
	// Ref is the git ref the build ran against, e.g. "refs/tags/v5.7.284".
	Ref string
	// Commit is the resolved commit SHA when the predicate records one.
	Commit string
	// FailReason is FailNone on success, otherwise the crypto/digest failure the
	// Verifier detected.
	FailReason FailReason
}

// Request carries the raw attestation bundle bytes (fetched by the caller, so
// fetching can be cached separately from verification) plus the registry artifact
// hash the attested subject must match.
type Request struct {
	// Bundle is the raw bytes of the registry attestation response (JSON with an
	// "attestations" array, each carrying a Sigstore bundle).
	Bundle []byte
	// ArtifactSHA512 is the lowercase-hex sha512 of the published tarball, taken
	// from the registry's dist.integrity, that the attestation subject must match.
	ArtifactSHA512 string
	// PackageName and Version identify the artifact, used to select the matching
	// subject within the bundle and for error context.
	PackageName string
	Version     string
}

// Verifier verifies build-provenance attestations. Implementations MUST perform
// full offline cryptographic verification against a pinned trust root — never
// trust the bundle's own contents without validating its signature first.
type Verifier interface {
	Verify(ctx context.Context, req Request) (Result, error)
}
