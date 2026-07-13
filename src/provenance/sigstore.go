package provenance

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// trustedRootJSON is the Sigstore public-good trust root, vendored for offline
// verification (the bundle carries its own log-inclusion proof; no live Rekor
// call is needed). Refresh with ./fetchtrustedroot if Sigstore rotates keys.
//
//go:embed trusted_root.json
var trustedRootJSON []byte

// githubActionsIssuer is the OIDC issuer for GitHub Actions. Because we do not
// pin the exact workflow SAN (we don't know it a priori), we require this issuer
// so a validly-signed-but-non-GitHub identity cannot pass as build provenance.
const githubActionsIssuer = "https://token.actions.githubusercontent.com"

// npmAttestationResponse is the shape of npm's attestations endpoint: a list of
// attestations, each wrapping a Sigstore bundle. npm publishes both a SLSA
// provenance and a publish attestation; only the former carries the source repo.
type npmAttestationResponse struct {
	Attestations []struct {
		PredicateType string          `json:"predicateType"`
		Bundle        json.RawMessage `json:"bundle"`
	} `json:"attestations"`
}

// SigstoreVerifier verifies attestation bundles offline against the embedded
// Sigstore public-good trust root.
type SigstoreVerifier struct {
	verifier *verify.Verifier
}

// NewSigstoreVerifier builds a verifier using the embedded trust root. It requires
// transparency-log inclusion and an observer (log) timestamp — both present in npm
// provenance bundles and necessary to establish that the short-lived Fulcio
// certificate was valid at signing time.
func NewSigstoreVerifier() (*SigstoreVerifier, error) {
	tr, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("loading embedded trusted root: %w", err)
	}
	v, err := verify.NewVerifier(tr,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("building verifier: %w", err)
	}
	return &SigstoreVerifier{verifier: v}, nil
}

// Verify performs full offline verification of a package version's build
// provenance. It verifies the signature chain and log inclusion first (so a bad
// signature is distinguishable from a digest mismatch), requires a GitHub Actions
// signing identity, then confirms the attested subject is this exact artifact.
func (s *SigstoreVerifier) Verify(_ context.Context, req Request) (Result, error) {
	if len(req.Bundle) == 0 {
		return Result{FailReason: FailNoAttestation}, nil
	}

	var resp npmAttestationResponse
	if err := json.Unmarshal(req.Bundle, &resp); err != nil {
		return Result{}, fmt.Errorf("parsing attestation response: %w", err)
	}
	if len(resp.Attestations) == 0 {
		return Result{FailReason: FailNoAttestation}, nil
	}

	want, err := decodeSHA512(req.ArtifactSHA512)
	if err != nil {
		return Result{}, fmt.Errorf("decoding artifact digest for %s@%s: %w", req.PackageName, req.Version, err)
	}
	wantHex := hex.EncodeToString(want)

	sawProvenance := false
	for _, att := range resp.Attestations {
		if !strings.Contains(att.PredicateType, "slsa.dev/provenance") {
			continue
		}
		sawProvenance = true

		b := &bundle.Bundle{}
		if err := b.UnmarshalJSON(att.Bundle); err != nil {
			continue
		}

		// Pass 1: full crypto verification WITHOUT binding the artifact, so a
		// signature/identity failure is distinguishable from a digest mismatch.
		result, err := s.verifier.Verify(b, verify.NewPolicy(
			verify.WithoutArtifactUnsafe(),
			verify.WithoutIdentitiesUnsafe(),
		))
		if err != nil {
			continue
		}

		cert := certOf(result)
		if cert == nil || cert.Issuer != githubActionsIssuer {
			continue // not a GitHub Actions build — don't trust as provenance
		}

		res := Result{
			SourceRepo: cert.SourceRepositoryURI,
			Ref:        cert.SourceRepositoryRef,
			Commit:     cert.SourceRepositoryDigest,
		}

		// Pass 2: the attested subject must be THIS artifact.
		if !subjectMatches(result.Statement, "sha512", wantHex) {
			res.FailReason = FailDigestMismatch
			return res, nil
		}
		res.Verified = true
		return res, nil
	}

	if sawProvenance {
		// A present-but-unverifiable provenance is a signal, not a soft miss.
		return Result{FailReason: FailInvalidSignature}, nil
	}
	return Result{FailReason: FailNoAttestation}, nil
}

func certOf(r *verify.VerificationResult) *certificate.Summary {
	if r == nil || r.Signature == nil {
		return nil
	}
	return r.Signature.Certificate
}

func subjectMatches(stmt *in_toto.Statement, algo, hexDigest string) bool {
	if stmt == nil {
		return false
	}
	for _, sub := range stmt.GetSubject() {
		if d, ok := sub.GetDigest()[algo]; ok && strings.EqualFold(d, hexDigest) {
			return true
		}
	}
	return false
}

// decodeSHA512 accepts the registry sha512 as base64 (npm SRI dist.integrity) or
// hex, returning the 64 raw bytes.
func decodeSHA512(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 64 {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 64 {
		return b, nil
	}
	return nil, fmt.Errorf("not a valid sha512 (base64 or hex): %q", s)
}
