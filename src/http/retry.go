package http

import (
	"context"
	"net/http"
	"net/url"
	"risk-guard/src/ctxutil"
	"slices"
	"time"

	"github.com/avast/retry-go/v4"
	"go.uber.org/zap"
)

const (
	DefaultMaxRetries   = 10
	DefaultInitialDelay = 10 * time.Second
	DefaultMaxDelay     = 300 * time.Second
)

func IsRetryableStatusCode(code int) bool {
	codesToRetry := []int{
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	}
	return slices.Contains(codesToRetry, code)
}

func maskURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid-url>"
	}
	u.RawQuery = ""
	u.User = nil
	return u.String()
}

func logRetryAttempt(ctx context.Context, attempt uint, err error, reqURL string) {
	logger := ctxutil.GetLogger(ctx)
	logger.Warn("retrying HTTP request",
		zap.Uint("attempt", attempt+1),
		zap.Uint("max_attempts", DefaultMaxRetries+1),
		zap.String("url", maskURL(reqURL)),
		zap.Error(err),
	)
}

// BuildRetryOptions constructs retry options with custom settings.
// Useful for tests or custom retry behavior.
func BuildRetryOptions(ctx context.Context, url string, maxRetries uint, initialDelay, maxDelay time.Duration) []retry.Option {
	return []retry.Option{
		retry.Attempts(maxRetries + 1),
		retry.Delay(initialDelay),
		retry.DelayType(retry.BackOffDelay),
		retry.MaxDelay(maxDelay),
		retry.Context(ctx),
		retry.RetryIf(func(err error) bool {
			statusCode, ok := GetStatusCodeFromError(err)
			if !ok {
				return false
			}
			return IsRetryableStatusCode(statusCode)
		}),
		retry.OnRetry(func(n uint, err error) {
			logRetryAttempt(ctx, n, err, url)
		}),
	}
}

func DefaultRetryOptions(ctx context.Context, url string) []retry.Option {
	// Check if custom retry options are provided in context
	if retryOpts, ok := GetRetryOptions(ctx); ok {
		return retryOpts
	}

	// Use default production retry settings
	return BuildRetryOptions(ctx, url, DefaultMaxRetries, DefaultInitialDelay, DefaultMaxDelay)
}
