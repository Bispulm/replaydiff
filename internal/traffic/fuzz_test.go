package traffic

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzScan feeds arbitrary bytes to the reader as a segment file. Whatever the
// input, Scan must not panic or allocate past its limits, and any record it
// returns must load and pass validation.
func FuzzScan(f *testing.F) {
	src := f.TempDir()
	enc, err := NewEncoder(EncoderOptions{})
	if err != nil {
		f.Fatal(err)
	}
	defer enc.Close()
	w, err := NewWriter(src, WriterOptions{})
	if err != nil {
		f.Fatal(err)
	}
	for seq := uint64(1); seq <= 2; seq++ {
		frame, err := enc.Encode(recordWithSeq(seq))
		if err != nil {
			f.Fatal(err)
		}
		if err := w.Append(frame); err != nil {
			f.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		f.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		f.Fatal(err)
	}
	valid, err := os.ReadFile(filepath.Join(src, entries[0].Name()))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(valid[:segmentHeaderSize])
	f.Add(valid[:len(valid)/2])
	f.Add([]byte{})
	f.Add([]byte("RDTRAFFC"))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "fuzz"+SealedSuffix), data, 0o600); err != nil {
			t.Fatal(err)
		}
		ds, err := Scan(dir, ScanOptions{MaxRecords: 1000, MaxFrameBytes: 1 << 20})
		if err != nil {
			return
		}
		defer func() { _ = ds.Close() }()
		for _, e := range ds.Entries {
			rec, err := ds.Load(e)
			if err != nil {
				t.Fatalf("indexed record failed to load: %v", err)
			}
			if err := rec.Validate(); err != nil {
				t.Fatalf("indexed record is invalid: %v", err)
			}
		}
	})
}
