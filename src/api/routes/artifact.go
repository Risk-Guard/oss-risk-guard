package routes

import "risk-guard/src/api/route"

type ArtifactExtraction struct {
	Ecosystem       string            `json:"ecosystem"`
	PackageName     string            `json:"package_name"`
	TarballFilename string            `json:"tarball_filename,omitempty"`
	Files           map[string]string `json:"files"`
	ArtifactURL     string            `json:"artifact_url,omitempty"`
	Verified        bool              `json:"verified"`
	VerifyError     *string           `json:"verify_error,omitempty"`
	SkipReason      *string           `json:"skip_reason,omitempty"`
}

type ArtifactParams struct {
	Ecosystem string
	Name      string
}

type ArtifactQuery struct {
	Version *string
}

var RouteArtifact = route.Route[ArtifactParams, ArtifactQuery, ArtifactExtraction]{
	Method:      "GET",
	Path:        "/artifact/package/{ecosystem}/{name}",
	OperationID: "getArtifactFiles",
	Summary:     "Get manifest files from a package artifact",
	Description: "Downloads a package artifact and extracts manifest/text files (e.g., package.json for npm, setup.py for pypi) without full disk extraction.",
	Tags:        []string{"artifact"},
}
