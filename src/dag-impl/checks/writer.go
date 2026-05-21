package checks

import (
	"context"

	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
)

type ChecksWriter func(ctx context.Context, doc storage.ChecksResult, input dag_impl.Input) error

type checksWriterKey struct{}

func SetChecksWriter(ctx context.Context, w ChecksWriter) context.Context {
	return context.WithValue(ctx, checksWriterKey{}, w)
}

func GetChecksWriter(ctx context.Context) ChecksWriter {
	w, _ := ctx.Value(checksWriterKey{}).(ChecksWriter)
	return w
}
