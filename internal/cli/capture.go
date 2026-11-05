package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Bispulm/replaydiff/internal/capture"
	"github.com/Bispulm/replaydiff/internal/redact"
)

const captureUsage = `Usage: replaydiff capture --upstream URL --out DIR --redact FILE [flags]

Proxy traffic to an upstream service and store redacted recordings. Live traffic
is forwarded even when recording fails. Final statistics are printed to stdout
as JSON when the process stops.

`

func runCapture(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var limits capture.Limits
	maxRequest := byteSize(1 << 20)
	maxResponse := byteSize(1 << 20)
	memoryBudget := byteSize(256 << 20)

	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:18200", "address to listen on")
	upstream := fs.String("upstream", "", "service to forward to (required)")
	out := fs.String("out", "", "directory for traffic segments (required)")
	policyPath := fs.String("redact", "", "redaction policy file, which may be empty (required)")
	secretEnv := fs.String("session-secret-env", "", "environment variable holding the session digest key; unset means a random key per process")
	logLevel := fs.String("log-level", "info", "debug, info, warn or error")
	shutdown := fs.Duration("shutdown-timeout", 10*time.Second, "time allowed for live requests to finish, and then again for queued records to drain")
	h2c := fs.Bool("h2c", false, "also accept HTTP/2 without TLS; for development")
	certFile := fs.String("tls-cert", "", "serve TLS with this certificate, negotiating HTTP/2")
	keyFile := fs.String("tls-key", "", "private key for --tls-cert")
	upstreamH2C := fs.Bool("upstream-h2c", false, "send to the upstream using HTTP/2 without TLS, with no fallback")
	upstreamCA := fs.String("upstream-ca-file", "", "PEM certificates to trust for an https upstream, instead of the system roots")
	fs.Var(&maxRequest, "max-request-body", "largest request body to record")
	fs.Var(&maxResponse, "max-response-body", "largest response body to record")
	fs.Var(&memoryBudget, "memory-budget", "bytes of body data to hold across all exchanges")
	fs.IntVar(&limits.QueueCapacity, "queue", 1024, "finished exchanges waiting to be recorded")
	fs.IntVar(&limits.Workers, "workers", 0, "redaction goroutines; 0 selects min(GOMAXPROCS, 4)")
	fs.Usage = func() {
		fmt.Fprint(stderr, captureUsage)
		fs.PrintDefaults()
	}
	help, err := parseFlags(fs, args, stderr)
	if help {
		return ExitOK
	}
	if err != nil {
		return fail(stderr, "capture", err)
	}

	switch {
	case *upstream == "":
		return fail(stderr, "capture", errors.New("--upstream is required"))
	case *out == "":
		return fail(stderr, "capture", errors.New("--out is required"))
	case *policyPath == "":
		return fail(stderr, "capture", errors.New("--redact is required, because it decides what stored bodies contain; pass an empty file to apply only the mandatory rules"))
	}
	logger, err := newLogger(stderr, *logLevel)
	if err != nil {
		return fail(stderr, "capture", err)
	}
	target, err := parseServiceURL("upstream", *upstream)
	if err != nil {
		return fail(stderr, "capture", err)
	}
	protocols, err := listenerProtocols(*h2c, *certFile, *keyFile)
	if err != nil {
		return fail(stderr, "capture", err)
	}
	upstreamTLS, err := loadCAFile("upstream-ca-file", *upstreamCA)
	if err != nil {
		return fail(stderr, "capture", err)
	}
	policy, err := redact.LoadPolicy(*policyPath)
	if err != nil {
		return fail(stderr, "capture", err)
	}
	var secret []byte
	if *secretEnv != "" {
		value, ok := os.LookupEnv(*secretEnv)
		if !ok || value == "" {
			return fail(stderr, "capture", fmt.Errorf("--session-secret-env: %s is not set", *secretEnv))
		}
		secret = []byte(value)
	}
	engine, err := redact.NewEngine(policy, redact.Options{SessionSecret: secret})
	if err != nil {
		return fail(stderr, "capture", err)
	}
	defer engine.Close()

	limits.MaxRequestBodyBytes = int64(maxRequest)
	limits.MaxResponseBodyBytes = int64(maxResponse)
	limits.MemoryBudgetBytes = int64(memoryBudget)
	recorder, err := capture.New(capture.Config{
		Upstream:    target,
		UpstreamH2C: *upstreamH2C,
		UpstreamTLS: upstreamTLS,
		Dir:         *out,
		Engine:      engine,
		Limits:      limits,
		Logger:      logger,
	})
	if err != nil {
		return fail(stderr, "capture", err)
	}

	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", *listen)
	if err != nil {
		closeCtx, cancel := context.WithTimeout(context.Background(), *shutdown)
		defer cancel()
		return fail(stderr, "capture", errors.Join(err, recorder.Close(closeCtx)))
	}
	server := &http.Server{
		Handler:           recorder,
		Protocols:         protocols,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          serverErrorLog(logger),
	}
	serveErr := make(chan error, 1)
	go func() {
		if *certFile != "" {
			serveErr <- server.ServeTLS(listener, *certFile, *keyFile)
			return
		}
		serveErr <- server.Serve(listener)
	}()
	logger.Info("capture listening", "addr", listener.Addr().String())

	var failure error
	select {
	case err := <-serveErr:
		failure = err
	case <-ctx.Done():
		logger.Info("capture stopping")
	}

	// Live requests get to finish, and their records are still accepted, before
	// recording stops.
	serverCtx, cancelServer := context.WithTimeout(context.Background(), *shutdown)
	defer cancelServer()
	if err := server.Shutdown(serverCtx); err != nil {
		logger.Warn("closing connections still active at the shutdown deadline")
		_ = server.Close()
	}
	recorderCtx, cancelRecorder := context.WithTimeout(context.Background(), *shutdown)
	defer cancelRecorder()
	if err := recorder.Close(recorderCtx); err != nil {
		failure = errors.Join(failure, err)
	}

	stats := recorder.Stats()
	if data, err := json.Marshal(stats); err == nil {
		fmt.Fprintf(stdout, "%s\n", data)
	}
	if len(stats.Dropped) > 0 {
		logger.Warn("recordings were dropped", "persisted", stats.Persisted, "observed", stats.Observed)
	}
	if failure != nil && !errors.Is(failure, http.ErrServerClosed) {
		return fail(stderr, "capture", failure)
	}
	return ExitOK
}
