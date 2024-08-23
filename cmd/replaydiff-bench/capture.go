package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
	"time"
)

// captureProcess is replaydiff capture running as its own process, as it would be
// deployed, writing to a local directory.
type captureProcess struct {
	cmd    *exec.Cmd
	stdout bytes.Buffer
	proxy  string
	done   chan struct{}
}

// CaptureStats is what capture prints when it stops, with its peak resident set.
type CaptureStats struct {
	Observed     int64            `json:"observed"`
	Persisted    int64            `json:"persisted"`
	Dropped      map[string]int64 `json:"dropped,omitempty"`
	PeakRSSBytes int64            `json:"peak_rss_bytes"`
}

// DroppedTotal sums drops over every reason.
func (s CaptureStats) DroppedTotal() int64 {
	var total int64
	for _, n := range s.Dropped {
		total += n
	}
	return total
}

var proxyAddr = regexp.MustCompile(`msg="capture listening" addr=(127\.0\.0\.1:\d+)`)

const benchPolicy = `json_paths: ["$.items[*].card"]` + "\n"

func startCapture(binary, upstream, dir string) (*captureProcess, error) {
	policy := filepath.Join(dir, "redact.yaml")
	if err := os.WriteFile(policy, []byte(benchPolicy), 0o600); err != nil {
		return nil, err
	}
	p := &captureProcess{done: make(chan struct{})}
	p.cmd = exec.CommandContext(context.Background(), binary, "capture", "--listen", "127.0.0.1:0",
		"--upstream", upstream, "--out", filepath.Join(dir, "traffic"), "--redact", policy)
	p.cmd.Stdout = &p.stdout
	stderr, err := p.cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := p.cmd.Start(); err != nil {
		return nil, err
	}
	found := make(chan string, 1)
	go func() {
		defer close(p.done)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			if m := proxyAddr.FindStringSubmatch(scanner.Text()); m != nil {
				found <- m[1]
			}
		}
		// The pipe closes when capture exits, which stop waits for separately.
		_ = scanner.Err()
	}()
	select {
	case addr := <-found:
		p.proxy = "http://" + addr
		return p, nil
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		return nil, errors.New("capture didn't report its address")
	}
}

// stop interrupts capture, waits for it to drain, and returns its statistics.
func (p *captureProcess) stop() (CaptureStats, error) {
	var stats CaptureStats
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
		return stats, err
	}
	<-p.done
	if err := p.cmd.Wait(); err != nil {
		return stats, fmt.Errorf("capture exited: %w", err)
	}
	if err := json.Unmarshal(bytes.TrimSpace(p.stdout.Bytes()), &stats); err != nil {
		return stats, fmt.Errorf("capture statistics: %w", err)
	}
	if usage, ok := p.cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
		stats.PeakRSSBytes = usage.Maxrss
		if runtime.GOOS == "linux" {
			stats.PeakRSSBytes *= 1024 // Linux reports kilobytes, macOS bytes.
		}
	}
	return stats, nil
}
