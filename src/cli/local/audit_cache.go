package main

import (
	"context"
	"path/filepath"
	"sort"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/local/auditcache"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"go.uber.org/zap"
)

type cacheConfig struct {
	enabled     bool
	dir         string
	maxAge      time.Duration
	policyHash  string
	builderHash string
}

func buildCacheConfig(checkMetadata []dag_builder.CheckInfo) (cacheConfig, error) {
	if auditNoCache {
		return cacheConfig{enabled: false}, nil
	}
	maxAge, err := auditcache.ParseMaxAge(auditMaxAge)
	if err != nil {
		return cacheConfig{}, err
	}
	if maxAge == 0 {
		return cacheConfig{enabled: false}, nil
	}
	dir := auditCacheDir
	if dir == "" {
		dir = filepath.Join(outputDir, "audit-cache")
	}
	policyHash, err := auditcache.PolicyHash(policyOverride, policyDefault)
	if err != nil {
		return cacheConfig{}, err
	}
	// GetAllCheckMetadata iterates a Go map, so order is non-deterministic.
	// Sort the codes so BuilderHash is stable across runs and the cache hits.
	codes := make([]string, 0, len(checkMetadata))
	for _, c := range checkMetadata {
		codes = append(codes, c.Code)
	}
	sort.Strings(codes)
	return cacheConfig{
		enabled:     true,
		dir:         dir,
		maxAge:      maxAge,
		policyHash:  policyHash,
		builderHash: auditcache.BuilderHash(codes),
	}, nil
}

// scoreOneCached wraps scoreOne with a filesystem cache lookup. Returns
// (run, age) where age >= 0 indicates a cache hit (with that age). Cache miss
// (or cache disabled) returns age = -1.
func scoreOneCached(ctx context.Context, key, overridesHash string, checkMetadata []dag_builder.CheckInfo, cc cacheConfig) (*sarif.Run, time.Duration) {
	logger := ctxutil.GetLogger(ctx)

	if !cc.enabled {
		return scoreOne(ctx, key, overridesHash, checkMetadata), -1
	}

	eco, name, version, err := parsePackageKey(key)
	if err != nil {
		return errorRun(name, key, err), -1
	}
	input := dag_impl.NewPackageInputWithVersion(eco, name, version, overridesHash)
	cacheKey := auditcache.Key(input.AnalysisIdentifier, cc.policyHash, cc.builderHash)

	if run, savedAt, hit, getErr := auditcache.Get(cc.dir, cacheKey, cc.maxAge); getErr != nil {
		logger.Warn("audit cache read failed; will rescore", zap.String("key", key), zap.Error(getErr))
	} else if hit {
		return run, time.Since(savedAt)
	}

	run := scoreOneWithInput(ctx, key, name, input, checkMetadata)
	if _, isAuditErr := summarizeRun(run); !isAuditErr {
		if err := auditcache.Put(cc.dir, cacheKey, run); err != nil {
			logger.Warn("audit cache write failed", zap.String("key", key), zap.Error(err))
		}
	}
	return run, -1
}

// roundDuration rounds a duration to a unit that reads naturally in CLI output.
func roundDuration(d time.Duration) time.Duration {
	switch {
	case d >= time.Hour:
		return d.Round(time.Minute)
	case d >= time.Minute:
		return d.Round(time.Second)
	default:
		return d.Round(time.Millisecond)
	}
}
