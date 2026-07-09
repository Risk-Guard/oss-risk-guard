package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	prettyconsole "github.com/thessem/zap-prettyconsole"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewLogger(level string) (*zap.Logger, error) {
	return NewLoggerWithWriter(level, zapcore.Lock(zapcore.AddSync(os.Stderr)))
}

// NewLoggerWithWriter builds the console logger against a caller-supplied
// writer (e.g. a progress.Line's LogWriter) instead of raw stderr, so log
// output can be coordinated with a live status line. The writer is expected to
// be concurrency-safe.
func NewLoggerWithWriter(level string, console zapcore.WriteSyncer) (*zap.Logger, error) {
	consoleLevel, err := parseLevel(level)
	if err != nil {
		return nil, err
	}

	encoder := prettyconsole.NewEncoder(prettyconsole.NewEncoderConfig())
	core := zapcore.NewCore(encoder, console, consoleLevel)
	return zap.New(core), nil
}

func NewLoggerWithFile(level, logPath string) (*zap.Logger, error) {
	return NewLoggerWithFileAndWriter(level, logPath, zapcore.Lock(zapcore.AddSync(os.Stderr)))
}

// NewLoggerWithFileAndWriter tees the console core (against the supplied writer)
// with a JSON file core, so a live status line and a debug logfile can coexist.
func NewLoggerWithFileAndWriter(level, logPath string, console zapcore.WriteSyncer) (*zap.Logger, error) {
	consoleLevel, err := parseLevel(level)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(logPath), 0o750); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	file, err := os.Create(logPath) //nolint:gosec // user-provided logfile path from CLI
	if err != nil {
		return nil, fmt.Errorf("failed to create log file: %w", err)
	}

	consoleConfig := prettyconsole.NewEncoderConfig()
	consoleEncoder := prettyconsole.NewEncoder(consoleConfig)
	consoleCore := zapcore.NewCore(
		consoleEncoder,
		console,
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
