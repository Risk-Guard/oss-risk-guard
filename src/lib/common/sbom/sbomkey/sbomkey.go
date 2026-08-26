// Package sbomkey recovers analysis-identifier keys from SBOM element
// identifiers, shared by the cdx16 and spdx30 readers.
package sbomkey

import (
	"encoding/base64"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/depsgraph"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/purl"
)

// Resolve returns the analysis-identifier key for an SBOM element. A ref that
// carries an encoded key is authoritative — it is the identifier the document
// actually wires its dependency edges with, and it may disagree with a purl
// derived from separately-recorded metadata. The purl is the fallback, and is
// what lets documents from other tools resolve at all.
func Resolve(ref, purlStr string) (string, bool) {
	if key, ok := DecodeRef(ref); ok {
		return key, true
	}
	return purl.ToAnalysisKey(purlStr)
}

// DecodeRef decodes the base64url-encoded key that the builders emit for
// elements with no purl. The prefix check is load-bearing: a foreign
// identifier such as a 36-character UUID decodes cleanly as base64url and
// would otherwise be handed on as a key full of binary garbage.
func DecodeRef(ref string) (string, bool) {
	if i := strings.LastIndex(ref, "#"); i >= 0 {
		ref = ref[i+1:]
	}
	decoded, err := base64.RawURLEncoding.DecodeString(ref)
	if err != nil {
		return "", false
	}
	key := string(decoded)
	if !strings.HasPrefix(key, "package/") && !strings.HasPrefix(key, "source/") {
		return "", false
	}
	return key, true
}

// StableNodePURL returns the node's purl, but only when it converts back to
// exactly key. A node whose recorded ecosystem and name disagree with its own
// analysis key would otherwise be published under an identifier that resolves
// to a different package, so those keep the encoded key instead.
func StableNodePURL(node depsgraph.SBOMNode, key string) string {
	p := NodePURL(node)
	if p == "" {
		return ""
	}
	if roundTripped, ok := purl.ToAnalysisKey(p); !ok || roundTripped != key {
		return ""
	}
	return p
}

// NodePURL builds a node's package URL, or "" when the node carries too little
// information to identify a package.
func NodePURL(node depsgraph.SBOMNode) string {
	if node.Ecosystem == nil || node.PackageName == nil {
		return ""
	}
	version := ""
	if node.PackageVersion != nil {
		version = *node.PackageVersion
	}
	return purl.Build(*node.Ecosystem, *node.PackageName, version)
}
