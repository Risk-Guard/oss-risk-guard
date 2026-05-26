package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/environment"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/cache"
	"github.com/Risk-Guard/oss-risk-guard/src/logger"
	"github.com/Risk-Guard/oss-risk-guard/src/runpath"
	"github.com/Risk-Guard/oss-risk-guard/src/version"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var rootCmd = &cobra.Command{
	Use:   "risk-guard-local <path>",
	Short: "Score a local on-disk git repository",
	Long: `Run the scoring DAG against an already-on-disk git repository.

The single argument must be a path to an existing git repository.

Cache outputs (DAG results, clones, audit cache, network cache) are written
under a single cache root, resolved in this order:
  1. --cache-dir flag
  2. RISK_GUARD_CACHE_DIR environment variable
  3. os.UserCacheDir()/risk-guard (platform default)

Examples:
  risk-guard-local .
  risk-guard-local /abs/path/to/repo
  risk-guard-local --cache-dir /var/cache/risk-guard /abs/path/to/repo`,
	Args: cobra.MaximumNArgs(1),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := environment.Load()
		if err != nil {
			return fmt.Errorf("failed to load environment configuration: %w", err)
		}

		logLevel, err := cmd.Flags().GetString("log-level")
		if err != nil {
			return fmt.Errorf("failed to get log-level flag: %w", err)
		}

		logfile, err := cmd.Flags().GetString("logfile")
		if err != nil {
			return fmt.Errorf("failed to get logfile flag: %w", err)
		}

		var log *zap.Logger
		if logfile != "" {
			log, err = logger.NewLoggerWithFile(logLevel, logfile)
			if err != nil {
				return fmt.Errorf("failed to create logger with file: %w", err)
			}
		} else {
			log, err = logger.NewLogger(logLevel)
			if err != nil {
				return fmt.Errorf("failed to create logger: %w", err)
			}
		}

		secureGit, err := cmd.Flags().GetBool("secure-git")
		if err != nil {
			return fmt.Errorf("failed to get secure-git flag: %w", err)
		}
		cfg.SecureGit = secureGit

		noColor, err := cmd.Flags().GetBool("no-color")
		if err != nil {
			return fmt.Errorf("failed to get no-color flag: %w", err)
		}
		if noColor {
			color.NoColor = true
		}

		ctx := environment.SetConfig(cmd.Context(), cfg)
		ctx = environment.SetSharedConfig(ctx, cfg)

		cacheDir, err := cmd.Flags().GetString("cache-dir")
		if err != nil {
			return fmt.Errorf("failed to get cache-dir flag: %w", err)
		}
		outputDirFlag, err := cmd.Flags().GetString("output-dir")
		if err != nil {
			return fmt.Errorf("failed to get output-dir flag: %w", err)
		}
		if outputDirFlag != "" && cacheDir == "" {
			fmt.Fprintln(os.Stderr, "warning: --output-dir is deprecated; use --cache-dir")
			cacheDir = outputDirFlag
		}
		resolvedCacheDir, err := resolveCacheDir(cacheDir)
		if err != nil {
			return fmt.Errorf("resolving cache dir: %w", err)
		}
		ctx = runpath.SetCacheDir(ctx, resolvedCacheDir)

		ctx = ctxutil.SetLogger(ctx, log)

		tmpDir, err := os.MkdirTemp("", "risk-guard-")
		if err != nil {
			return fmt.Errorf("creating temp directory: %w", err)
		}
		ctx = ctxutil.SetTempDir(ctx, tmpDir)

		cmd.SetContext(ctx)
		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		defer func() {
			if r := recover(); r != nil {
				return
			}
		}()

		log := ctxutil.GetLogger(cmd.Context())

		backend := cache.GetCacheBackend(cmd.Context())
		if backend != nil {
			if err := backend.Close(); err != nil {
				log.Warn("failed to close cache backend", zap.Error(err))
			}
		}

		if tmpDir := ctxutil.GetTempDir(cmd.Context()); tmpDir != "" && tmpDir != os.TempDir() {
			if err := os.RemoveAll(tmpDir); err != nil {
				log.Warn("failed to remove temp directory", zap.String("path", tmpDir), zap.Error(err))
			}
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		showVersion, _ := cmd.Flags().GetBool("version")
		if showVersion {
			fmt.Printf("risk-guard-local version:\n")
			fmt.Printf("  Git Hash: %s\n", version.GetBuildGitHash())
			fmt.Printf("  Build Time: %s\n", version.GetBuildTime())
			return nil
		}
		if len(args) == 0 {
			return cmd.Help()
		}
		return runScoreLocal(cmd, args)
	},
}

func init() {
	rootCmd.Flags().BoolP("version", "v", false, "Print version information")
	rootCmd.PersistentFlags().String("log-level", "warn", "Set logging level (debug, info, warn, error)")
	rootCmd.PersistentFlags().Bool("secure-git", false, "Isolate git from local config/credentials (blocks SSH keys, credential helpers)")
	rootCmd.PersistentFlags().String("logfile", "", "Write debug logs to file (in addition to console)")
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable colored output (also honors NO_COLOR env var and non-TTY stderr)")
	rootCmd.PersistentFlags().String("cache-dir", "", "Single cache root for DAG outputs, clones, audit cache, and network cache (default: $RISK_GUARD_CACHE_DIR or os.UserCacheDir()/risk-guard).")

	registerLocalFlags(rootCmd)
}

// resolveCacheDir picks the cache root in precedence order:
// flagValue (already resolved by the caller from --cache-dir, or the deprecated
// --output-dir) > RISK_GUARD_CACHE_DIR env > os.UserCacheDir()/risk-guard.
// Falls back to os.MkdirTemp if no user cache dir is available.
func resolveCacheDir(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if env := os.Getenv("RISK_GUARD_CACHE_DIR"); env != "" {
		return env, nil
	}
	cacheBase, err := os.UserCacheDir()
	if err != nil {
		tmp, mkErr := os.MkdirTemp("", "risk-guard-")
		if mkErr != nil {
			return "", fmt.Errorf("user cache dir unavailable (%v) and tmp fallback failed: %w", err, mkErr)
		}
		return tmp, nil
	}
	return filepath.Join(cacheBase, "risk-guard"), nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
