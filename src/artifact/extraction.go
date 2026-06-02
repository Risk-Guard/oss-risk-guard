package artifact

// ArtifactExtraction holds the manifest/text files extracted from a package
// artifact, along with hash-verification status.
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
