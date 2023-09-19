// Package e2e exercises the built binaries as separate processes over real
// sockets. It is the closest test to what a user runs.
package e2e

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	buildOnce sync.Once
	binDir    string
	errBuild  error
)

// TestMain owns the shared build directory so it can be removed after all
// tests finish.
func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		_ = os.RemoveAll(binDir)
	}
	os.Exit(code)
}

// binary returns the path of a command under cmd/, building all of them once.
func binary(t *testing.T, name string) string {
	t.Helper()
	buildOnce.Do(func() {
		binDir, errBuild = os.MkdirTemp("", "replaydiff-e2e-bin-")
		if errBuild != nil {
			return
		}
		cmd := exec.CommandContext(context.Background(), "go", "build", "-o", binDir+string(filepath.Separator), "../../cmd/...")
		out, err := cmd.CombinedOutput()
		if err != nil {
			errBuild = &buildError{err: err, output: string(out)}
		}
	})
	if errBuild != nil {
		t.Fatalf("build: %v", errBuild)
	}
	return filepath.Join(binDir, name)
}

type buildError struct {
	err    error
	output string
}

func (e *buildError) Error() string { return e.err.Error() + ": " + e.output }

// process is a running binary whose combined log output is retained, so tests
// can both find its listen address and scan it for sensitive values.
type process struct {
	cmd  *exec.Cmd
	mu   sync.Mutex
	logs strings.Builder
	addr chan string
	done chan error
}

var listenAddr = regexp.MustCompile(`addr=(127\.0\.0\.1:\d+)`)

func start(t *testing.T, env []string, name string, args ...string) *process {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), binary(t, name), args...)
	cmd.Env = append(os.Environ(), env...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = io.Discard
	p := &process{cmd: cmd, addr: make(chan string, 1), done: make(chan error, 1)}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var drained sync.WaitGroup
	drained.Go(func() {
		sc := bufio.NewScanner(stderr)
		sent := false
		for sc.Scan() {
			line := sc.Text()
			p.mu.Lock()
			p.logs.WriteString(line + "\n")
			p.mu.Unlock()
			if m := listenAddr.FindStringSubmatch(line); m != nil && !sent {
				p.addr <- m[1]
				sent = true
			}
		}
	})
	go func() {
		drained.Wait()
		p.done <- cmd.Wait()
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
		}
	})
	return p
}

// baseURL waits for the process to report its listen address.
func (p *process) baseURL(t *testing.T) string {
	t.Helper()
	select {
	case addr := <-p.addr:
		return "http://" + addr
	case <-time.After(15 * time.Second):
		t.Fatalf("no listen address; logs:\n%s", p.output())
		return ""
	}
}

// stop sends SIGTERM and waits for a clean exit.
func (p *process) stop(t *testing.T) error {
	t.Helper()
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-p.done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatalf("process did not exit; logs:\n%s", p.output())
		return nil
	}
}

func (p *process) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.logs.String()
}

func httpGet(t *testing.T, url string, header map[string]string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}
