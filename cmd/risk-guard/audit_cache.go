package main

import (
	"context"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/local/auditcache"
	"github.com/Risk-Guard/oss-risk-guard/src/runpath"
	"github.com/Risk-Guard/oss-risk-guard/src/violations"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"
	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	"go.uber.org/zap"
)

type cacheConfig struct {
	enabled bool
	dir     string
	maxAge  time.Duration
}

func buildCacheConfig(ctx context.Context) (cacheConfig, error) {
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
	return cacheConfig{
		enabled: true,
		dir:     runpath.GetAuditCacheDir(ctx),
		maxAge:  maxAge,
	}, nil
}

// scoreOneCached wraps scoreOne with a filesystem cache lookup. Returns
// (analysis, age, err) where age >= 0 indicates a cache hit. Cache miss
// (or cache disabled) returns age = -1. err is non-nil only on a hard
// scoring failure that should be surfaced as an audit error.
func scoreOneCached(ctx context.Context, key, overridesHash string, checkMetadata []dag_builder.CheckInfo, cc cacheConfig) (*violations.AnalysisViolations, time.Duration, error) {
	logger := ctxutil.GetLogger(ctx)

	if !cc.enabled {
		analysis, err := scoreOne(ctx, key, overridesHash, checkMetadata)
		return analysis, -1, err
	}

	eco, name, version, err := parsePackageKey(key)
	if err != nil {
		return nil, -1, err
	}
	input := dag_impl.NewPackageInputWithVersion(eco, name, version, overridesHash)
	cacheKey := auditcache.Key(input.AnalysisIdentifier)

	if analysis, savedAt, hit, getErr := auditcache.Get(cc.dir, cacheKey, cc.maxAge); getErr != nil {
		logger.Warn("audit cache read failed; will rescore", zap.String("key", key), zap.Error(getErr))
	} else if hit && analysis != nil {
		return analysis, time.Since(savedAt), nil
	}

	analysis, scoreErr := scoreOneWithInput(ctx, key, name, input, checkMetadata)
	if scoreErr == nil && analysis != nil {
		if err := auditcache.Put(cc.dir, cacheKey, analysis); err != nil {
			logger.Warn("audit cache write failed", zap.String("key", key), zap.Error(err))
		}
	}
	return analysis, -1, scoreErr
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
