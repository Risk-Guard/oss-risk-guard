// Package runpath carries per-run filesystem paths on the context: the single
// cache root and any explicit input dir for --no-fetch replays. These are
// runtime values set by command wiring, not env vars, so they live on ctx
// rather than on environment.Config.
package runpath

import (
	"context"
	"path/filepath"
)

type (
	cacheDirKey         struct{}
	inputDirKey         struct{}
	checksOutputPathKey struct{}
)

// SetCacheDir stores the single cache root. All cache subdirs (dag, clones,
// audit, network) are computed relative to this root.
func SetCacheDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, cacheDirKey{}, dir)
}

// GetCacheDir returns the cache root.
func GetCacheDir(ctx context.Context) string {
	dir, _ := ctx.Value(cacheDirKey{}).(string)
	return dir
}

// GetDAGCacheDir is where DAG node yml outputs are written and read back from
// during --no-fetch replays.
func GetDAGCacheDir(ctx context.Context) string {
	return filepath.Join(GetCacheDir(ctx), "dag")
}

// GetCloneCacheDir is where per-package unpacked git working trees live.
func GetCloneCacheDir(ctx context.Context) string {
	return filepath.Join(GetCacheDir(ctx), "clones")
}

// GetAuditCacheDir is where the audit-cache stores per-package raw violations.
// The "audit-v2" subdir is a deliberate break from the legacy "audit" subdir
// (which held graded SARIF runs) so old entries are silently orphaned rather
// than mis-decoded.
func GetAuditCacheDir(ctx context.Context) string {
	return filepath.Join(GetCacheDir(ctx), "audit-v2")
}

// GetNetworkCacheDir is the root for the cache backend's filesystem storage:
// compressed clone tarballs, registry JSON, HTTP response cache.
func GetNetworkCacheDir(ctx context.Context) string {
	return filepath.Join(GetCacheDir(ctx), "network")
}

func SetInputDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, inputDirKey{}, dir)
}

// GetInputDir returns the explicit --input-dir if set, otherwise falls back
// to the DAG cache. The fallback lets a single-run flow read its own ymls
// without the caller having to set --input-dir.
func GetInputDir(ctx context.Context) string {
	if dir, ok := ctx.Value(inputDirKey{}).(string); ok && dir != "" {
		return dir
	}
	return GetDAGCacheDir(ctx)
}

func SetChecksOutputPath(ctx context.Context, path string) context.Context {
	return context.WithValue(ctx, checksOutputPathKey{}, path)
}

func GetChecksOutputPath(ctx context.Context) string {
	path, _ := ctx.Value(checksOutputPathKey{}).(string)
	return path
}

// SetOutputDir is a deprecated alias for SetCacheDir. Kept so the deprecated
// --output-dir flag keeps working while callers migrate.
//
// Deprecated: use SetCacheDir.
func SetOutputDir(ctx context.Context, dir string) context.Context {
	return SetCacheDir(ctx, dir)
}

// GetOutputDir is a deprecated alias for GetCacheDir.
//
// Deprecated: use GetCacheDir.
func GetOutputDir(ctx context.Context) string {
	return GetCacheDir(ctx)
}
