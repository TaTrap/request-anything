package process

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strconv"
	"time"
)

const (
	MaxOutputBytes = 1 << 20 // 1 MiB cap per stream
	QuickTimeout   = 60 * time.Second
	BuildTimeout   = 10 * time.Minute
)

// Output captures process exit status and capped stdout/stderr buffers.
type Output struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
	TimedOut bool
}

// Run executes a subprocess safely with stdin isolation, output cap, and tree termination on timeout.
// Subprocess stdout is always captured into Output.Stdout and NEVER leaked to the parent's stdout.
func Run(ctx context.Context, dir string, timeout time.Duration, stdin []byte, env []string, program string, args ...string) (*Output, error) {
	if timeout <= 0 {
		timeout = QuickTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, program, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if len(env) > 0 {
		cmd.Env = env
	}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var outBuf, errBuf cappedBuffer
	outBuf.limit = MaxOutputBytes
	errBuf.limit = MaxOutputBytes
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", program, err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		code := 0
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				code = exitErr.ExitCode()
			} else {
				code = -1
			}
		}
		return &Output{
			ExitCode: code,
			Stdout:   outBuf.Bytes(),
			Stderr:   errBuf.Bytes(),
		}, err
	case <-cctx.Done():
		killProcessTree(cmd)
		<-done
		return &Output{
			ExitCode: -1,
			Stdout:   outBuf.Bytes(),
			Stderr:   errBuf.Bytes(),
			TimedOut: true,
		}, fmt.Errorf("command `%s` timed out after %s", program, timeout)
	}
}

func killProcessTree(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if runtime.GOOS == "windows" {
		_ = exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
	}
	_ = cmd.Process.Kill()
}

type cappedBuffer struct {
	limit int
	buf   bytes.Buffer
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	_, _ = c.buf.Write(p)
	if c.limit > 0 && c.buf.Len() > c.limit {
		excess := c.buf.Len() - c.limit
		b := c.buf.Bytes()
		c.buf.Reset()
		c.buf.Write(b[excess:])
	}
	return len(p), nil
}

func (c *cappedBuffer) Bytes() []byte {
	b := make([]byte, c.buf.Len())
	copy(b, c.buf.Bytes())
	return b
}

var _ io.Writer = (*cappedBuffer)(nil)
