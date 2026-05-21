package spdx30

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ReadDirectDeps returns the analysis-identifier keys for the SBOM's direct
// (depth=1) dependencies. Keys are decoded from the SPDX spdxId suffix
// produced by Builder (base64 of the original key).
func ReadDirectDeps(raw []byte) ([]string, error) {
	var doc struct {
		Graph []json.RawMessage `json:"@graph"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decoding SPDX: %w", err)
	}

	type rel struct {
		RelationshipType string   `json:"relationshipType"`
		From             string   `json:"from"`
		To               []string `json:"to"`
	}

	rels := make([]rel, 0)
	var rootElement string
	for _, node := range doc.Graph {
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(node, &head); err != nil {
			continue
		}
		switch head.Type {
		case "Relationship":
			var r rel
			if err := json.Unmarshal(node, &r); err == nil {
				rels = append(rels, r)
			}
		case "SpdxDocument":
			var d struct {
				RootElement []string `json:"rootElement"`
			}
			if err := json.Unmarshal(node, &d); err == nil && len(d.RootElement) > 0 {
				rootElement = d.RootElement[0]
			}
		}
	}

	if rootElement == "" {
		return nil, fmt.Errorf("SPDX missing rootElement")
	}

	var directIDs []string
	for _, r := range rels {
		if r.RelationshipType == RelationshipDependsOn && r.From == rootElement {
			directIDs = append(directIDs, r.To...)
		}
	}

	refs := make([]string, 0, len(directIDs))
	for _, id := range directIDs {
		if i := strings.LastIndex(id, "#"); i >= 0 {
			refs = append(refs, id[i+1:])
		}
	}
	return decodeRefs(refs), nil
}

func decodeRefs(refs []string) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		decoded, err := base64.RawURLEncoding.DecodeString(r)
		if err != nil {
			continue
		}
		out = append(out, string(decoded))
	}
	return out
}
