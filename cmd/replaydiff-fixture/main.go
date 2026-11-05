// Command replaydiff-fixture runs the synthetic service used by tests and the
// demo. It holds no real data and is not meant for any other purpose.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Bispulm/replaydiff/internal/fixture"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "replaydiff-fixture:", err)
		os.Exit(2)
	}
}

func run() error {
	listen := flag.String("listen", "127.0.0.1:18201", "listen address")
	variant := flag.String("variant", string(fixture.Baseline), "baseline or candidate")
	instance := flag.String("instance", "a", "replica name, used in noise fields")
	latency := flag.Duration("candidate-latency", 40*time.Millisecond, "extra latency on the candidate's daily report route")
	flag.Parse()

	svc, err := fixture.New(fixture.Options{
		Variant:          fixture.Variant(*variant),
		Instance:         *instance,
		CandidateLatency: *latency,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", *listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: svc, ReadHeaderTimeout: 5 * time.Second}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	slog.Info("fixture listening", "addr", ln.Addr().String(), "variant", *variant, "instance", *instance)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
