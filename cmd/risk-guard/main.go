package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	Use:   "risk-guard <path>",
	Short: "Run the full pipeline: source scoring + SBOM + dep audit → one SARIF",
	Long: `Run the complete risk-guard pipeline against an on-disk git repository:
score the local source, build an SBOM in memory, audit each direct dependency,
and emit a single merged SARIF report containing the local-source Run plus one
Run per audited package.

The single argument must be a path to an existing git repository.

For source-only scoring (no dependency audit) use the "scan" subcommand.

Cache outputs (DAG results, clones, audit cache, network cache) are written
under a single cache root, resolved in this order:
  1. --cache-dir flag
  2. RISK_GUARD_CACHE_DIR environment variable
  3. os.UserCacheDir()/risk-guard (platform default)

Examples:
  risk-guard .
  risk-guard /abs/path/to/repo --sarif report.sarif
  risk-guard . --sbom-format cyclonedx --sbom-out sbom.cdx.json
  risk-guard . --continue-on-error=false`,
	Args:          cobra.MaximumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
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

		// --clone-timeout wins over $CLONE_TIMEOUT_SECONDS, but only when set so
		// the env value (or default) survives when the flag is omitted.
		if cmd.Flags().Changed("clone-timeout") {
			d, err := cmd.Flags().GetDuration("clone-timeout")
			if err != nil {
				return fmt.Errorf("failed to get clone-timeout flag: %w", err)
			}
			cfg.CloneTimeoutSeconds = int(d.Seconds())
		}

		colorMode, err := cmd.Flags().GetString("color")
		if err != nil {
			return fmt.Errorf("failed to get color flag: %w", err)
		}
		noColor, err := cmd.Flags().GetBool("no-color")
		if err != nil {
			return fmt.Errorf("failed to get no-color flag: %w", err)
		}
		if err := resolveColor(colorMode, noColor); err != nil {
			return err
		}

		ctx := environment.SetConfig(cmd.Context(), cfg)
		ctx = environment.SetSharedConfig(ctx, cfg)

		cacheDir, err := cmd.Flags().GetString("cache-dir")
		if err != nil {
			return fmt.Errorf("failed to get cache-dir flag: %w", err)
		}
		// --output-dir is only registered on subcommands that predated --cache-dir;
		// look it up best-effort so the root command (which omits it) still works.
		if f := cmd.Flags().Lookup("output-dir"); f != nil && f.Value.String() != "" && cacheDir == "" {
			fmt.Fprintln(os.Stderr, "warning: --output-dir is deprecated; use --cache-dir")
			cacheDir = f.Value.String()
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
			fmt.Printf("risk-guard version:\n")
			fmt.Printf("  Git Hash: %s\n", version.GetBuildGitHash())
			fmt.Printf("  Build Time: %s\n", version.GetBuildTime())
			return nil
		}
		if len(args) == 0 {
			return cmd.Help()
		}
		return runAll(cmd, args)
	},
}

func init() {
	rootCmd.Flags().BoolP("version", "v", false, "Print version information")
	rootCmd.PersistentFlags().String("log-level", "warn", "Set logging level (debug, info, warn, error)")
	rootCmd.PersistentFlags().Bool("secure-git", false, "Isolate git from local config/credentials (blocks SSH keys, credential helpers)")
	rootCmd.PersistentFlags().Duration("clone-timeout", 0, "Per-git-clone timeout, e.g. 30s or 2m (overrides $CLONE_TIMEOUT_SECONDS; default 30s)")
	rootCmd.PersistentFlags().String("logfile", "", "Write debug logs to file (in addition to console)")
	rootCmd.PersistentFlags().String("color", "auto", "Colored output: auto (default; honors TTY + NO_COLOR), always, never")
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable colored output (deprecated: use --color=never)")
	_ = rootCmd.PersistentFlags().MarkDeprecated("no-color", "use --color=never")

	// Make the cache-dir default concrete: resolve the platform default
	// (option 3) now so help shows the real path instead of the abstract
	// "os.UserCacheDir()/risk-guard".
	cacheHelp := "Single cache root for DAG outputs, clones, audit cache, and network cache (default: $RISK_GUARD_CACHE_DIR)."
	if def := platformDefaultCacheDir(); def != "" {
		cacheHelp = fmt.Sprintf("Single cache root for DAG outputs, clones, audit cache, and network cache (default: $RISK_GUARD_CACHE_DIR, else %s).", def)
		rootCmd.Long = strings.Replace(rootCmd.Long,
			"os.UserCacheDir()/risk-guard (platform default)",
			fmt.Sprintf("os.UserCacheDir()/risk-guard (%s — platform default)", def), 1)
	}
	rootCmd.PersistentFlags().String("cache-dir", "", cacheHelp)

	registerRunAllFlags(rootCmd)
}

// registerRunAllFlags wires the flags for the unified pipeline root command.
// Reuses the same package-level globals as the audit/scan subcommands so the
// shared `evaluate`, `scoreAll`, and `buildCacheConfig` helpers pick them up.
func registerRunAllFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&sarifOutFile, "sarif", "", "Output file for merged SARIF report (default ./risk-guard-report.sarif)")
	cmd.Flags().StringVar(&policyOverride, "policy-override", "", "Policy file that completely overrides all policy (YAML)")
	cmd.Flags().StringVar(&policyDefault, "policy-default", "", "Policy file to use as base instead of global default (YAML)")
	cmd.Flags().StringVar(&runAllSBOMFormat, "sbom-format", sbomFormatSPDX, "In-memory SBOM format used to enumerate deps: spdx or cyclonedx")
	cmd.Flags().StringVar(&runAllSBOMOut, "sbom-out", "", "Also persist the generated SBOM to this path (optional)")
	cmd.Flags().IntVar(&auditJobs, "jobs", 4, "Maximum number of packages to audit in parallel")
	cmd.Flags().StringVar(&auditMaxAge, "max-age", "48h", "Maximum audit cache age (e.g. 30m, 48h). 0 disables caching")
	cmd.Flags().BoolVar(&auditNoCache, "no-cache", false, "Force fresh audit scoring; do not read or write the audit cache")
	cmd.Flags().BoolVar(&runAllContinueOnError, "continue-on-error", true, "Continue and emit a partial SARIF when SBOM/audit steps fail")
	cmd.Flags().BoolVar(&runAllGitHub, "github", false, "After writing SARIF, render GitHub Actions workflow annotations to stdout")
	cmd.Flags().StringVar(&runAllGitLab, "gitlab", "", "After writing SARIF, write a GitLab Code Quality (CodeClimate) report to this file (e.g. gl-code-quality-report.json)")
	cmd.Flags().StringVar(&runAllModeOverride, "mode", "", "Override workflow.mode from .risk-guard.yml: active (fail on blocking findings), silent (never fail), disabled (refuse to run)")
	cmd.Flags().BoolVar(&runAllRiskGuard, "risk-guard", false, "Offload the audit: run source checks locally, then upload the SBOM + source findings to the Risk Guard server to score the dependencies")
	cmd.Flags().StringVar(&runAllRGCommit, "commit", "", "Commit SHA to associate the run with (default: HEAD); only with --risk-guard")
	cmd.Flags().StringVar(&runAllRGToken, "token", "", "GitHub token for the Risk Guard server (default: $RISK_GUARD_TOKEN, $GITHUB_TOKEN, or 'gh auth token'); only with --risk-guard")
	cmd.Flags().StringVar(&runAllRGServer, "server", "", "Risk Guard server base URL (default: $RISK_GUARD_URL or https://ossriskguard.app); only with --risk-guard")
	registerLevelFlag(cmd)
}

// resolveColor maps the --color value (with --no-color back-compat) onto the
// fatih/color global. "always" forces color even when stderr is not a TTY,
// overriding both auto-detection and NO_COLOR; "never" disables it; "auto"
// leaves fatih's own TTY + NO_COLOR detection intact. An explicit
// --color=always|never beats the deprecated --no-color.
func resolveColor(colorMode string, noColor bool) error {
	switch colorMode {
	case "always":
		color.NoColor = false
	case "never":
		color.NoColor = true
	case "auto", "":
		if noColor {
			color.NoColor = true
		}
	default:
		return fmt.Errorf("invalid --color %q: want auto, always, or never", colorMode)
	}
	return nil
}

// resolveCacheDir picks the cache root in precedence order:
// flagValue (already resolved by the caller from --cache-dir, or the deprecated
// --output-dir) > RISK_GUARD_CACHE_DIR env > os.UserCacheDir()/risk-guard.
// Falls back to os.MkdirTemp if no user cache dir is available.
// platformDefaultCacheDir returns the OS-default cache root — option 3 of the
// resolution order (os.UserCacheDir()/risk-guard) — or "" when the user cache
// dir is unavailable. Used only to make help text concrete.
func platformDefaultCacheDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "risk-guard")
}

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
		// Blocking findings already explained themselves via SARIF/annotations;
		// printing "Error: blocking findings detected" on top is noise.
		if !errors.Is(err, errBlockingFindings) && !errors.Is(err, errReported) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}
