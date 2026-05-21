# ecosystem

Two-phase manifest handling for ecosystems and package managers

## API

```go
// Phase 1: Detection (cheap) - find manifests, identify package manager
manifests, err := ecosystem.DetectManifests(dir)

// Phase 2: Parsing (expensive) - extract dependencies
for _, m := range manifests {
    parsed, err := ecosystem.ParseManifest(m, repoRoot)
}
```

## Structure

```
ecosystem/
├── detect.go              # Top-level orchestrator
├── parse.go               # Top-level router
└── <ecosystem>/
    ├── detect.go          # Ecosystem-specific detection
    ├── parse.go           # Ecosystem-specific parsing
    ├── lockfiles.go       # Lockfile detection wrapper
    └── package_manager/   # Per-package-manager lockfile detectors
```

## Package Manager Detection

Detection infers `PackageManager` from lockfile presence in the manifest directory (searching upward to repo root). Each ecosystem defines its own lockfile-to-manager mapping.
