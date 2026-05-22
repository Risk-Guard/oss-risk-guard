// Package runpath carries per-run filesystem paths on the context: where to
// write outputs, where to read cached inputs, the per-repo cache dir, and the
// checks output file. These are runtime values set by command wiring, not env
// vars, so they live on ctx rather than on environment.Config.
package runpath

import "context"

type (
	outputDirKey        struct{}
	inputDirKey         struct{}
	repoOutputDirKey    struct{}
	checksOutputPathKey struct{}
)

func SetOutputDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, outputDirKey{}, dir)
}

func GetOutputDir(ctx context.Context) string {
	dir, _ := ctx.Value(outputDirKey{}).(string)
	return dir
}

func SetInputDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, inputDirKey{}, dir)
}

// GetInputDir returns the explicit input dir if set, otherwise falls back to
// the output dir. Callers that want cached results from a prior run set
// InputDir explicitly; the fallback keeps single-run flows simple.
func GetInputDir(ctx context.Context) string {
	if dir, ok := ctx.Value(inputDirKey{}).(string); ok && dir != "" {
		return dir
	}
	return GetOutputDir(ctx)
}

func SetRepoOutputDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, repoOutputDirKey{}, dir)
}

func SetChecksOutputPath(ctx context.Context, path string) context.Context {
	return context.WithValue(ctx, checksOutputPathKey{}, path)
}

func GetChecksOutputPath(ctx context.Context) string {
	path, _ := ctx.Value(checksOutputPathKey{}).(string)
	return path
}
