package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/Bispulm/replaydiff/internal/traffic"
)

const inspectUsage = `Usage: replaydiff inspect --traffic DIR [flags]

Print stored records as JSON lines, one record per line, with text bodies
decoded so they can be read and reviewed. Use this to check what redaction left
in a recording before sharing it.

Exits 2 if the dataset is damaged or incomplete, after printing what is readable.

`

// inspectedBody is a stored body with its data shown as text where possible.
type inspectedBody struct {
	traffic.Body
	Data       []byte `json:"data,omitempty"`
	DataText   string `json:"data_text,omitempty"`
	DataBase64 []byte `json:"data_base64,omitempty"`
}

func inspectBody(body traffic.Body) inspectedBody {
	out := inspectedBody{Body: body}
	if utf8.Valid(body.Data) {
		out.DataText = string(body.Data)
	} else {
		out.DataBase64 = body.Data
	}
	return out
}

func runInspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	dir := fs.String("traffic", "", "directory of traffic segments (required)")
	limit := fs.Int("limit", 0, "print at most this many records; 0 prints all")
	fs.Usage = func() {
		fmt.Fprint(stderr, inspectUsage)
		fs.PrintDefaults()
	}
	help, err := parseFlags(fs, args, stderr)
	if help {
		return ExitOK
	}
	if err != nil {
		return fail(stderr, "inspect", err)
	}
	if *dir == "" {
		return fail(stderr, "inspect", errors.New("--traffic is required"))
	}
	dataset, err := traffic.Scan(*dir, traffic.ScanOptions{})
	if err != nil {
		return fail(stderr, "inspect", err)
	}
	defer func() { _ = dataset.Close() }()

	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	for i, entry := range dataset.Entries {
		if *limit > 0 && i >= *limit {
			break
		}
		rec, err := dataset.Load(entry)
		if err != nil {
			return fail(stderr, "inspect", err)
		}
		if err := enc.Encode(inspectable(rec)); err != nil {
			return fail(stderr, "inspect", err)
		}
	}

	fmt.Fprintf(stderr, "%d record(s) in %d segment(s)\n", dataset.Integrity.Records, dataset.Integrity.Segments)
	for _, reason := range sortedKeys(dataset.CaptureDrops) {
		fmt.Fprintf(stderr, "capture dropped %d exchange(s): %s\n", dataset.CaptureDrops[reason], reason)
	}
	if problems := dataset.Integrity.Problems(); len(problems) > 0 {
		for _, problem := range problems {
			fmt.Fprintf(stderr, "incomplete: %s\n", problem)
		}
		return ExitFailure
	}
	return ExitOK
}

// inspectable mirrors traffic.Record, replacing its bodies with readable forms.
func inspectable(rec *traffic.Record) any {
	type request struct {
		traffic.Request
		Body inspectedBody `json:"body"`
	}
	type response struct {
		traffic.Response
		Body inspectedBody `json:"body"`
	}
	type record struct {
		*traffic.Record
		Request  request   `json:"request"`
		Response *response `json:"response,omitempty"`
	}
	out := record{Record: rec, Request: request{Request: rec.Request, Body: inspectBody(rec.Request.Body)}}
	if rec.Response != nil {
		out.Response = &response{Response: *rec.Response, Body: inspectBody(rec.Response.Body)}
	}
	return out
}
