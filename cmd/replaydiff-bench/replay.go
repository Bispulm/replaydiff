package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"time"

	"github.com/Bispulm/replaydiff/internal/replay"
	"github.com/Bispulm/replaydiff/internal/traffic"
)

// session is a run of records sharing a session key, which replay keeps in order.
type session struct {
	key     string
	records int
}

// writeDataset writes replayable GET records, in arrival order session by session.
func writeDataset(dir string, sessions []session) (map[string]string, error) {
	enc, err := traffic.NewEncoder(traffic.EncoderOptions{})
	if err != nil {
		return nil, err
	}
	defer enc.Close()
	w, err := traffic.NewWriter(dir, traffic.WriterOptions{})
	if err != nil {
		return nil, err
	}
	sessionOf := map[string]string{}
	seq := uint64(0)
	now := time.Now()
	for _, s := range sessions {
		for i := range s.records {
			seq++
			rec := &traffic.Record{
				SchemaVersion: traffic.SchemaVersion,
				ID:            traffic.NewID(now),
				Seq:           seq,
				CapturedAt:    now,
				SessionKey:    s.key,
				Protocol:      traffic.ProtocolHTTP11,
				Request:       traffic.Request{Method: http.MethodGet, Path: fmt.Sprintf("/v1/orders/ord-%d", i), Body: traffic.Body{State: traffic.BodyEmpty}},
				Outcome:       traffic.Outcome{Transport: traffic.TransportOK},
				Redaction:     traffic.Redaction{Complete: true},
				Replay:        traffic.ReplayInfo{Eligible: true},
			}
			sessionOf[rec.ID] = s.key
			frame, err := enc.Encode(rec)
			if err != nil {
				return nil, err
			}
			if err := w.Append(frame); err != nil {
				return nil, err
			}
		}
	}
	return sessionOf, w.Close()
}

// replayRun replays a dataset against three local targets that answer at once, and
// returns when each record finished, relative to the start.
func replayRun(ctx context.Context, dir string) (*replay.Summary, map[string]time.Duration, error) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"ord-1","status":"shipped"}`))
	})
	var urls []string
	for range 3 {
		server := httptest.NewServer(handler)
		defer server.Close()
		urls = append(urls, server.URL)
	}
	engine, err := replay.New(replay.Config{
		BaselineA:      replay.TargetConfig{URL: urls[0]},
		BaselineB:      replay.TargetConfig{URL: urls[1]},
		Candidate:      replay.TargetConfig{URL: urls[2]},
		AllowedOrigins: urls,
	})
	if err != nil {
		return nil, nil, err
	}
	defer engine.Close()
	dataset, err := traffic.Scan(dir, traffic.ScanOptions{})
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = dataset.Close() }()
	var mu sync.Mutex
	finished := map[string]time.Duration{}
	start := time.Now()
	summary, err := engine.Run(ctx, dataset, func(result *replay.RecordResult) {
		mu.Lock()
		finished[result.ID] = time.Since(start)
		mu.Unlock()
	})
	return summary, finished, err
}

// ReplayResult is the replay rate on a dataset of independent records.
type ReplayResult struct {
	Records          int     `json:"records"`
	Replayed         int     `json:"replayed"`
	RecordsPerSecond float64 `json:"records_per_second"`
	CallsPerSecond   float64 `json:"calls_per_second"`
	Complete         bool    `json:"complete"`
}

func measureReplay(ctx context.Context, work string, records int) (ReplayResult, error) {
	dir := filepath.Join(work, "replay")
	sessions := make([]session, records)
	for i := range sessions {
		sessions[i] = session{key: fmt.Sprintf("%032x", i+1), records: 1}
	}
	if _, err := writeDataset(dir, sessions); err != nil {
		return ReplayResult{}, err
	}
	summary, _, err := replayRun(ctx, dir)
	if err != nil {
		return ReplayResult{}, err
	}
	return ReplayResult{
		Records:          summary.Records,
		Replayed:         summary.Replayed,
		RecordsPerSecond: summary.RecordsPerSecond,
		CallsPerSecond:   summary.UpstreamCallsPerSecond,
		Complete:         summary.Complete(),
	}, nil
}

// FairnessResult says how long short sessions waited behind a long one.
type FairnessResult struct {
	LongRecords          int     `json:"long_records"`
	ShortSessions        int     `json:"short_sessions"`
	ShortRecords         int     `json:"short_records_each"`
	LastShortFinishShare float64 `json:"last_short_session_finished_at_share_of_run"`
	RunSeconds           float64 `json:"run_seconds"`
}

func measureFairness(ctx context.Context, work string, long, shorts, each int) (FairnessResult, error) {
	dir := filepath.Join(work, "fairness")
	sessions := []session{{key: fmt.Sprintf("%032x", 1), records: long}}
	for i := range shorts {
		sessions = append(sessions, session{key: fmt.Sprintf("%032x", i+2), records: each})
	}
	sessionOf, err := writeDataset(dir, sessions)
	if err != nil {
		return FairnessResult{}, err
	}
	_, finished, err := replayRun(ctx, dir)
	if err != nil {
		return FairnessResult{}, err
	}
	longKey := sessions[0].key
	var lastShort, end time.Duration
	for id, at := range finished {
		end = max(end, at)
		if sessionOf[id] != longKey {
			lastShort = max(lastShort, at)
		}
	}
	result := FairnessResult{LongRecords: long, ShortSessions: shorts, ShortRecords: each, RunSeconds: end.Seconds()}
	if end > 0 {
		result.LastShortFinishShare = lastShort.Seconds() / end.Seconds()
	}
	return result, nil
}
