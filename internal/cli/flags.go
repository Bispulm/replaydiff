package cli

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
)

// parseFlags parses args into fs. A nil error with help true means help was
// requested. Parse errors are written to stderr by the flag package.
func parseFlags(fs *flag.FlagSet, args []string, stderr io.Writer) (help bool, err error) {
	fs.SetOutput(stderr)
	err = fs.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if fs.NArg() > 0 {
		return false, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return false, nil
}

// fail prints an error and returns the failure exit code.
func fail(stderr io.Writer, command string, err error) int {
	fmt.Fprintf(stderr, "replaydiff %s: %v\n", command, err)
	return ExitFailure
}

// byteSize is a flag holding a positive size such as 512KiB or 1MiB.
type byteSize int64

func (b *byteSize) String() string { return strconv.FormatInt(int64(*b), 10) }

func (b *byteSize) Set(value string) error {
	n, err := parseByteSize(value)
	if err != nil {
		return err
	}
	*b = byteSize(n)
	return nil
}

func parseByteSize(value string) (int64, error) {
	multiplier := int64(1)
	number := value
	// Longest first: every suffix ends in B.
	for _, unit := range []struct {
		suffix string
		size   int64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"B", 1}} {
		if trimmed, ok := strings.CutSuffix(value, unit.suffix); ok {
			number, multiplier = trimmed, unit.size
			break
		}
	}
	n, err := strconv.ParseInt(number, 10, 64)
	if err != nil || n <= 0 || n > math.MaxInt64/multiplier {
		return 0, fmt.Errorf("invalid size %q: want a positive number with an optional B, KiB, MiB or GiB suffix", value)
	}
	return n * multiplier, nil
}

// parseServiceURL validates an operator-supplied service URL. Errors never echo
// the value, since it may hold credentials.
func parseServiceURL(flagName, value string) (*url.URL, error) {
	u, err := url.Parse(value)
	switch {
	case err != nil:
		return nil, fmt.Errorf("--%s: not a valid URL", flagName)
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, fmt.Errorf("--%s: scheme must be http or https", flagName)
	case u.Host == "":
		return nil, fmt.Errorf("--%s: host is required", flagName)
	case u.User != nil:
		return nil, fmt.Errorf("--%s: credentials aren't allowed in the URL", flagName)
	case u.RawQuery != "" || u.Fragment != "":
		return nil, fmt.Errorf("--%s: a query or fragment isn't allowed", flagName)
	}
	return u, nil
}

func newLogger(stderr io.Writer, level string) (*slog.Logger, error) {
	var parsed slog.Level
	if err := parsed.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("--log-level: unknown level %q", level)
	}
	return slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: parsed})), nil
}

// serverErrorLog adapts net/http's internal logger. Its messages can quote
// request data, and a panic message can hold anything, so the text is discarded
// and only the fact of an error is logged.
func serverErrorLog(logger *slog.Logger) *log.Logger {
	return log.New(writerFunc(func(p []byte) (int, error) {
		logger.Debug("http server reported an error; text withheld because it can quote traffic")
		return len(p), nil
	}), "", 0)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// loadCAFile reads PEM certificates into a client TLS config. An empty path
// returns nil, which means the system's trusted roots.
func loadCAFile(flagName, path string) (*tls.Config, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // The path is the operator's own flag.
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", flagName, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("--%s: no PEM certificates found", flagName)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// listenerProtocols validates how the proxy accepts connections and returns the
// protocols to serve. Cleartext HTTP/2 is opt-in, since it only suits development.
func listenerProtocols(h2c bool, certFile, keyFile string) (*http.Protocols, error) {
	switch {
	case certFile != "" && keyFile == "":
		return nil, errors.New("--tls-cert needs --tls-key")
	case keyFile != "" && certFile == "":
		return nil, errors.New("--tls-key needs --tls-cert")
	case h2c && certFile != "":
		return nil, errors.New("--h2c is cleartext and can't be combined with --tls-cert; TLS negotiates HTTP/2 by itself")
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	switch {
	case h2c:
		protocols.SetUnencryptedHTTP2(true)
	case certFile != "":
		protocols.SetHTTP2(true)
	}
	return protocols, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
