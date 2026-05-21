package unsupported

// ManifestInfo describes an unsupported manifest file type.
type ManifestInfo struct {
	Filename       string // exact match (e.g., "go.mod")
	GlobSuffix     string // suffix match (e.g., ".gemspec" matches "*.gemspec")
	Language       string // display name: "Go", "Rust", "Java", etc.
	Ecosystem      string // canonical: "go", "cargo", "maven"
	OSVEcosystem   string // for OSV API queries
	GHSAEcosystem  string // for GHSA API queries
	PackageManager string // display: "Go Modules", "Cargo", "Maven"
}

// Manifests contains all unsupported manifest file definitions.
// Each entry maps to an ecosystem that we cannot currently parse for dependencies.
var Manifests = []ManifestInfo{
	// Go
	{Filename: "go.mod", Language: "Go", Ecosystem: "go", OSVEcosystem: "Go", GHSAEcosystem: "go", PackageManager: "Go Modules"},
	{Filename: "go.sum", Language: "Go", Ecosystem: "go", OSVEcosystem: "Go", GHSAEcosystem: "go", PackageManager: "Go Modules"},

	// Rust
	{Filename: "Cargo.toml", Language: "Rust", Ecosystem: "cargo", OSVEcosystem: "crates.io", GHSAEcosystem: "rust", PackageManager: "Cargo"},
	{Filename: "Cargo.lock", Language: "Rust", Ecosystem: "cargo", OSVEcosystem: "crates.io", GHSAEcosystem: "rust", PackageManager: "Cargo"},

	// Java
	{Filename: "pom.xml", Language: "Java", Ecosystem: "maven", OSVEcosystem: "Maven", GHSAEcosystem: "maven", PackageManager: "Maven"},
	{Filename: "build.gradle", Language: "Java", Ecosystem: "maven", OSVEcosystem: "Maven", GHSAEcosystem: "maven", PackageManager: "Gradle"},
	{Filename: "build.gradle.kts", Language: "Java/Kotlin", Ecosystem: "maven", OSVEcosystem: "Maven", GHSAEcosystem: "maven", PackageManager: "Gradle"},

	// C#/.NET
	{GlobSuffix: ".csproj", Language: "C#/.NET", Ecosystem: "nuget", OSVEcosystem: "NuGet", GHSAEcosystem: "nuget", PackageManager: "NuGet"},
	{Filename: "packages.config", Language: "C#/.NET", Ecosystem: "nuget", OSVEcosystem: "NuGet", GHSAEcosystem: "nuget", PackageManager: "NuGet"},
	{Filename: "Directory.Build.props", Language: "C#/.NET", Ecosystem: "nuget", OSVEcosystem: "NuGet", GHSAEcosystem: "nuget", PackageManager: "NuGet"},

	// C/C++
	{Filename: "CMakeLists.txt", Language: "C/C++", Ecosystem: "cmake", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "CMake"},
	{Filename: "conanfile.txt", Language: "C/C++", Ecosystem: "conan", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Conan"},
	{Filename: "conanfile.py", Language: "C/C++", Ecosystem: "conan", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Conan"},
	{Filename: "vcpkg.json", Language: "C/C++", Ecosystem: "vcpkg", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "vcpkg"},

	// PHP
	{Filename: "composer.json", Language: "PHP", Ecosystem: "packagist", OSVEcosystem: "Packagist", GHSAEcosystem: "composer", PackageManager: "Composer"},
	{Filename: "composer.lock", Language: "PHP", Ecosystem: "packagist", OSVEcosystem: "Packagist", GHSAEcosystem: "composer", PackageManager: "Composer"},

	// Swift
	{Filename: "Package.swift", Language: "Swift", Ecosystem: "swift", OSVEcosystem: "SwiftURL", GHSAEcosystem: "swift", PackageManager: "Swift PM"},
	{Filename: "Package.resolved", Language: "Swift", Ecosystem: "swift", OSVEcosystem: "SwiftURL", GHSAEcosystem: "swift", PackageManager: "Swift PM"},

	// Scala
	{Filename: "build.sbt", Language: "Scala", Ecosystem: "maven", OSVEcosystem: "Maven", GHSAEcosystem: "maven", PackageManager: "sbt"},
	{Filename: "build.sc", Language: "Scala", Ecosystem: "maven", OSVEcosystem: "Maven", GHSAEcosystem: "maven", PackageManager: "Mill"},

	// R
	{Filename: "DESCRIPTION", Language: "R", Ecosystem: "cran", OSVEcosystem: "CRAN", GHSAEcosystem: "", PackageManager: "CRAN"},
	{Filename: "renv.lock", Language: "R", Ecosystem: "cran", OSVEcosystem: "CRAN", GHSAEcosystem: "", PackageManager: "renv"},

	// Julia
	{Filename: "Project.toml", Language: "Julia", Ecosystem: "julia", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Pkg"},
	{Filename: "Manifest.toml", Language: "Julia", Ecosystem: "julia", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Pkg"},

	// Perl
	{Filename: "cpanfile", Language: "Perl", Ecosystem: "cpan", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "CPAN"},
	{Filename: "META.json", Language: "Perl", Ecosystem: "cpan", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "CPAN"},
	{Filename: "META.yml", Language: "Perl", Ecosystem: "cpan", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "CPAN"},
	{Filename: "Makefile.PL", Language: "Perl", Ecosystem: "cpan", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "CPAN"},

	// Lua
	{GlobSuffix: ".rockspec", Language: "Lua", Ecosystem: "luarocks", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "LuaRocks"},

	// Haskell
	{GlobSuffix: ".cabal", Language: "Haskell", Ecosystem: "hackage", OSVEcosystem: "Hackage", GHSAEcosystem: "", PackageManager: "Hackage"},
	{Filename: "stack.yaml", Language: "Haskell", Ecosystem: "hackage", OSVEcosystem: "Hackage", GHSAEcosystem: "", PackageManager: "Stackage"},
	{Filename: "cabal.project", Language: "Haskell", Ecosystem: "hackage", OSVEcosystem: "Hackage", GHSAEcosystem: "", PackageManager: "Hackage"},

	// Elixir
	{Filename: "mix.exs", Language: "Elixir", Ecosystem: "hex", OSVEcosystem: "Hex", GHSAEcosystem: "hex", PackageManager: "Hex"},
	{Filename: "mix.lock", Language: "Elixir", Ecosystem: "hex", OSVEcosystem: "Hex", GHSAEcosystem: "hex", PackageManager: "Hex"},

	// OCaml
	{Filename: "dune-project", Language: "OCaml", Ecosystem: "opam", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "opam"},
	{GlobSuffix: ".opam", Language: "OCaml", Ecosystem: "opam", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "opam"},

	// Clojure
	{Filename: "deps.edn", Language: "Clojure", Ecosystem: "clojars", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Clojars"},
	{Filename: "project.clj", Language: "Clojure", Ecosystem: "clojars", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Clojars"},

	// Nim
	{GlobSuffix: ".nimble", Language: "Nim", Ecosystem: "nimble", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Nimble"},

	// Zig
	{Filename: "build.zig.zon", Language: "Zig", Ecosystem: "zig", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Zig PM"},

	// Fortran
	{Filename: "fpm.toml", Language: "Fortran", Ecosystem: "fpm", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "fpm"},

	// Ada
	{Filename: "alire.toml", Language: "Ada", Ecosystem: "alire", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Alire"},
	{GlobSuffix: ".gpr", Language: "Ada", Ecosystem: "alire", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Alire"},

	// Delphi
	{GlobSuffix: ".dproj", Language: "Delphi", Ecosystem: "delphi", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Boss"},
	{Filename: "boss.json", Language: "Delphi", Ecosystem: "delphi", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Boss"},

	// Docker/Container
	{Filename: "Dockerfile", Language: "Docker", Ecosystem: "docker", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Docker Hub"},
	{Filename: "docker-compose.yml", Language: "Docker", Ecosystem: "docker", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Docker Hub"},
	{Filename: "docker-compose.yaml", Language: "Docker", Ecosystem: "docker", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Docker Hub"},

	// Kubernetes/Helm
	{Filename: "Chart.yaml", Language: "Kubernetes", Ecosystem: "helm", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Helm"},

	// Terraform
	{GlobSuffix: ".tf", Language: "Terraform", Ecosystem: "terraform", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Terraform Registry"},
	{Filename: ".terraform.lock.hcl", Language: "Terraform", Ecosystem: "terraform", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Terraform Registry"},

	// Ansible
	{Filename: "galaxy.yml", Language: "Ansible", Ecosystem: "ansible", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Ansible Galaxy"},

	// Homebrew
	{Filename: "Brewfile", Language: "Homebrew", Ecosystem: "homebrew", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "Homebrew"},

	// Nix
	{Filename: "flake.nix", Language: "Nix", Ecosystem: "nix", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "nixpkgs"},
	{Filename: "default.nix", Language: "Nix", Ecosystem: "nix", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "nixpkgs"},
	{Filename: "shell.nix", Language: "Nix", Ecosystem: "nix", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "nixpkgs"},

	// Bazel
	{Filename: "MODULE.bazel", Language: "Bazel", Ecosystem: "bazel", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "BCR"},
	{Filename: "WORKSPACE", Language: "Bazel", Ecosystem: "bazel", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "BCR"},
	{Filename: "WORKSPACE.bazel", Language: "Bazel", Ecosystem: "bazel", OSVEcosystem: "", GHSAEcosystem: "", PackageManager: "BCR"},

	// Python (unsupported formats only - Pipfile is not supported)
	{Filename: "Pipfile", Language: "Python", Ecosystem: "pypi", OSVEcosystem: "PyPI", GHSAEcosystem: "pip", PackageManager: "pipenv"},
	{Filename: "Pipfile.lock", Language: "Python", Ecosystem: "pypi", OSVEcosystem: "PyPI", GHSAEcosystem: "pip", PackageManager: "pipenv"},

	// JavaScript (unsupported formats only - lock files are not parsed)
	{Filename: "package-lock.json", Language: "JavaScript/Node", Ecosystem: "npm", OSVEcosystem: "npm", GHSAEcosystem: "npm", PackageManager: "npm"},
	{Filename: "yarn.lock", Language: "JavaScript/Node", Ecosystem: "npm", OSVEcosystem: "npm", GHSAEcosystem: "npm", PackageManager: "yarn"},
	{Filename: "pnpm-lock.yaml", Language: "JavaScript/Node", Ecosystem: "npm", OSVEcosystem: "npm", GHSAEcosystem: "npm", PackageManager: "pnpm"},
	{Filename: "bun.lockb", Language: "JavaScript/Node", Ecosystem: "npm", OSVEcosystem: "npm", GHSAEcosystem: "npm", PackageManager: "bun"},
}

func (m *ManifestInfo) Matches(filename string) bool {
	if m.Filename != "" && filename == m.Filename {
		return true
	}
	if m.GlobSuffix != "" && len(filename) > len(m.GlobSuffix) {
		suffix := filename[len(filename)-len(m.GlobSuffix):]
		return suffix == m.GlobSuffix
	}
	return false
}

func FindManifestInfo(filename string) *ManifestInfo {
	for i := range Manifests {
		if Manifests[i].Matches(filename) {
			return &Manifests[i]
		}
	}
	return nil
}

var SparseCheckoutPatterns = []string{
	// Go
	"**/go.mod",
	"**/go.sum",
	// Rust
	"**/Cargo.toml",
	"**/Cargo.lock",
	// Java
	"**/pom.xml",
	"**/build.gradle",
	"**/build.gradle.kts",
	// C#/.NET
	"**/*.csproj",
	"**/packages.config",
	"**/Directory.Build.props",
	// C/C++
	"**/CMakeLists.txt",
	"**/conanfile.txt",
	"**/conanfile.py",
	"**/vcpkg.json",
	// PHP
	"**/composer.json",
	"**/composer.lock",
	// Swift
	"**/Package.swift",
	"**/Package.resolved",
	// Scala
	"**/build.sbt",
	"**/build.sc",
	// R
	"**/DESCRIPTION",
	"**/renv.lock",
	// Julia
	"**/Project.toml",
	"**/Manifest.toml",
	// Perl
	"**/cpanfile",
	"**/META.json",
	"**/META.yml",
	"**/Makefile.PL",
	// Lua
	"**/*.rockspec",
	// Haskell
	"**/*.cabal",
	"**/stack.yaml",
	"**/cabal.project",
	// Elixir
	"**/mix.exs",
	"**/mix.lock",
	// OCaml
	"**/dune-project",
	"**/*.opam",
	// Clojure
	"**/deps.edn",
	"**/project.clj",
	// Nim
	"**/*.nimble",
	// Zig
	"**/build.zig.zon",
	// Fortran
	"**/fpm.toml",
	// Ada
	"**/alire.toml",
	"**/*.gpr",
	// Delphi
	"**/*.dproj",
	"**/boss.json",
	// Docker
	"**/Dockerfile",
	"**/docker-compose.yml",
	"**/docker-compose.yaml",
	// Kubernetes/Helm
	"**/Chart.yaml",
	// Terraform
	"**/*.tf",
	"**/.terraform.lock.hcl",
	// Ansible
	"**/galaxy.yml",
	// Homebrew
	"**/Brewfile",
	// Nix
	"**/flake.nix",
	"**/default.nix",
	"**/shell.nix",
	// Bazel
	"**/MODULE.bazel",
	"**/WORKSPACE",
	"**/WORKSPACE.bazel",
	// Python (unsupported)
	"**/Pipfile",
	"**/Pipfile.lock",
	// JavaScript (unsupported)
	"**/package-lock.json",
	"**/yarn.lock",
	"**/pnpm-lock.yaml",
	"**/bun.lockb",
}
