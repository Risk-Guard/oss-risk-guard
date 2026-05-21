package logger

import (
	"fmt"
	"os"
	"strings"

	"github.com/blendle/zapdriver"
	prettyconsole "github.com/thessem/zap-prettyconsole"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewLogger(level string) (*zap.Logger, error) {
	var zapLevel zapcore.Level
	switch strings.ToLower(level) {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn", "warning":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		return nil, fmt.Errorf("invalid log level: %s (must be debug, info, warn, or error)", level)
	}

	config := prettyconsole.NewConfig()
	config.Level = zap.NewAtomicLevelAt(zapLevel)
	config.DisableCaller = true
	config.DisableStacktrace = true
	config.OutputPaths = []string{"stderr"}
	config.ErrorOutputPaths = []string{"stderr"}

	logger, err := config.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build logger: %w", err)
	}

	return logger, nil
}

func NewStructuredLogger(level, projectID string) (*zap.Logger, error) {
	var zapLevel zapcore.Level
	switch strings.ToLower(level) {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn", "warning":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		return nil, fmt.Errorf("invalid log level: %s (must be debug, info, warn, or error)", level)
	}

	config := zapdriver.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapLevel)
	config.OutputPaths = []string{"stderr"}
	config.ErrorOutputPaths = []string{"stderr"}

	logger, err := config.Build(zapdriver.WrapCore(
		zapdriver.ReportAllErrors(true),
	))
	if err != nil {
		return nil, fmt.Errorf("failed to build structured logger: %w", err)
	}

	if projectID != "" {
		logger = logger.With(zapdriver.Label("project_id", projectID))
	}

	return logger, nil
}

func NewLoggerWithFile(level, filepath string) (*zap.Logger, error) {
	consoleLevel, err := parseLevel(level)
	if err != nil {
		return nil, err
	}

	file, err := os.Create(filepath) //nolint:gosec // user-provided logfile path from CLI
	if err != nil {
		return nil, fmt.Errorf("failed to create log file: %w", err)
	}

	consoleConfig := prettyconsole.NewEncoderConfig()
	consoleEncoder := prettyconsole.NewEncoder(consoleConfig)
	consoleCore := zapcore.NewCore(
		consoleEncoder,
		zapcore.AddSync(os.Stderr),
		consoleLevel,
	)

	fileEncoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	fileCore := zapcore.NewCore(
		fileEncoder,
		zapcore.AddSync(file),
		zapcore.DebugLevel,
	)

	core := zapcore.NewTee(consoleCore, fileCore)
	return zap.New(core), nil
}

func parseLevel(level string) (zapcore.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return zapcore.DebugLevel, nil
	case "info":
		return zapcore.InfoLevel, nil
	case "warn", "warning":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("invalid log level: %s (must be debug, info, warn, or error)", level)
	}
}
