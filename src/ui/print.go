package ui

import (
	"fmt"
	"io"

	"go.uber.org/zap/zapcore"
)

// Printf writes a line above the live rows: erase the block, print, repaint.
// Use it for every human-facing line — log output, per-package audit results,
// verdicts. Writing to os.Stderr directly instead would tear the rows, because
// the cursor arithmetic assumes nothing else moves the cursor.
//
// A console write that fails is not actionable for these callers, so the error
// is dropped here. Write, which backs the logger, does report it.
func (u *UI) Printf(format string, a ...any) { _ = u.print(fmt.Sprintf(format, a...)) }

func (u *UI) print(s string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.enabled {
		return u.emit(s)
	}
	u.eraseLocked()
	err := u.emit(s)
	u.redrawLocked()
	return err
}

// Write lets a UI act as the zap console sink. Unlike a dropped spinner frame,
// a dropped log line is real output loss, so the error reaches the logger
// rather than being swallowed. In non-interactive mode this path is the only
// sink for console logs, which is exactly where losing them goes unnoticed.
func (u *UI) Write(p []byte) (int, error) {
	if err := u.print(string(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// LogWriter returns a WriteSyncer for the zap console core.
func (u *UI) LogWriter() zapcore.WriteSyncer { return zapcore.AddSync(u) }

// emit writes s in full. io.WriteString does not loop, so a short write is
// retried rather than silently truncating the line.
func (u *UI) emit(s string) error {
	for len(s) > 0 {
		n, err := io.WriteString(u.w, s)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		s = s[n:]
	}
	return nil
}

// paint emits a rendered frame. Frames are disposable — the next tick redraws
// the same state — so a failed paint is dropped rather than latched. Log lines
// and result lines go through print, which does report failure.
func (u *UI) paint(s string) { _ = u.emit(s) }
