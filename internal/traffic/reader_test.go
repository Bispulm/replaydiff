package traffic

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// writeSegments writes records 1..n and closes the writer cleanly.
func writeSegments(t *testing.T, dir string, n int, opts WriterOptions) {
	t.Helper()
	enc := newTestEncoder(t)
	w, err := NewWriter(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	for seq := 1; seq <= n; seq++ {
		if err := w.Append(mustFrame(t, enc, recordWithSeq(uint64(seq)))); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func onlySegment(t *testing.T, dir string) string {
	t.Helper()
	names := segmentFiles(t, dir)
	if len(names) != 1 {
		t.Fatalf("files = %v, want one", names)
	}
	return filepath.Join(dir, names[0])
}

func mustScan(t *testing.T, dir string) *Dataset {
	t.Helper()
	ds, err := Scan(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	t.Cleanup(func() { _ = ds.Close() })
	return ds
}

func seqs(ds *Dataset) []uint64 {
	out := make([]uint64, 0, len(ds.Entries))
	for _, e := range ds.Entries {
		out = append(out, e.Seq)
	}
	return out
}

func TestScanRoundTripsRecords(t *testing.T) {
	dir := t.TempDir()
	writeSegments(t, dir, 5, WriterOptions{})

	ds := mustScan(t, dir)
	if !ds.Integrity.Complete() {
		t.Fatalf("integrity problems on a clean dataset: %v", ds.Integrity.Problems())
	}
	if got := seqs(ds); !reflect.DeepEqual(got, []uint64{1, 2, 3, 4, 5}) {
		t.Fatalf("seqs = %v", got)
	}
	got, err := ds.Load(ds.Entries[2])
	if err != nil {
		t.Fatal(err)
	}
	want := recordWithSeq(3)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load mismatch:\nwant %+v\ngot  %+v", want, got)
	}
}

func TestEntryExposesFieldsNeededForScheduling(t *testing.T) {
	dir := t.TempDir()
	writeSegments(t, dir, 1, WriterOptions{})
	e := mustScan(t, dir).Entries[0]
	want := recordWithSeq(1)
	if e.SessionKey != want.SessionKey || e.Method != want.Request.Method || !e.Replay.Eligible {
		t.Fatalf("entry = %+v", e)
	}
}

func TestScanSpansRotatedSegments(t *testing.T) {
	dir := t.TempDir()
	writeSegments(t, dir, 4, WriterOptions{MaxSegmentBytes: 1})
	ds := mustScan(t, dir)
	if !ds.Integrity.Complete() {
		t.Fatalf("problems: %v", ds.Integrity.Problems())
	}
	if ds.Integrity.Segments != 4 || len(ds.Entries) != 4 {
		t.Fatalf("segments = %d, entries = %d", ds.Integrity.Segments, len(ds.Entries))
	}
}

func TestEmptyDirectoryIsAnError(t *testing.T) {
	if _, err := Scan(t.TempDir(), ScanOptions{}); !errors.Is(err, ErrNoSegments) {
		t.Fatalf("err = %v, want ErrNoSegments", err)
	}
}

func TestMissingDirectoryIsAnError(t *testing.T) {
	if _, err := Scan(filepath.Join(t.TempDir(), "absent"), ScanOptions{}); err == nil {
		t.Fatal("want error")
	}
}

func TestPartialFinalRecordRecoversEarlierRecords(t *testing.T) {
	dir := t.TempDir()
	enc := newTestEncoder(t)
	w, err := NewWriter(dir, WriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for seq := uint64(1); seq <= 3; seq++ {
		if err := w.Append(mustFrame(t, enc, recordWithSeq(seq))); err != nil {
			t.Fatal(err)
		}
	}
	// Simulates a crash: the process dies mid-write and never seals.
	path := onlySegment(t, dir)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, info.Size()-5); err != nil {
		t.Fatal(err)
	}

	ds := mustScan(t, dir)
	if got := seqs(ds); !reflect.DeepEqual(got, []uint64{1, 2}) {
		t.Fatalf("seqs = %v", got)
	}
	if ds.Integrity.PartialTails != 1 || ds.Integrity.UnsealedSegments != 1 {
		t.Fatalf("integrity = %+v", ds.Integrity)
	}
	if ds.Integrity.Complete() {
		t.Fatal("dataset with a torn tail must not be complete")
	}
}

func TestLostTailAtFrameBoundaryIsDetected(t *testing.T) {
	dir := t.TempDir()
	writeSegments(t, dir, 3, WriterOptions{})
	path := onlySegment(t, dir)

	// Remove the footer exactly, leaving a file that ends on a frame boundary
	// with no parse error to hint that anything is missing.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	footerStart := lastFrameOffset(t, data)
	if err := os.WriteFile(path, data[:footerStart], 0o600); err != nil {
		t.Fatal(err)
	}

	ds := mustScan(t, dir)
	if ds.Integrity.Complete() {
		t.Fatal("a segment without a footer must not be complete")
	}
	if ds.Integrity.UnsealedSegments != 1 {
		t.Fatalf("integrity = %+v", ds.Integrity)
	}
}

// lastFrameOffset walks a well-formed segment and returns the final frame's offset.
func lastFrameOffset(t *testing.T, data []byte) int {
	t.Helper()
	off, last := segmentHeaderSize, 0
	for off < len(data) {
		last = off
		off += frameHeaderSize + int(binary.BigEndian.Uint32(data[off+12:]))
	}
	return last
}

func frameOffsets(data []byte) []int {
	var out []int
	for off := segmentHeaderSize; off < len(data); off += frameHeaderSize + int(binary.BigEndian.Uint32(data[off+12:])) {
		out = append(out, off)
	}
	return out
}

func TestCorruptPayloadSkipsOnlyThatRecord(t *testing.T) {
	dir := t.TempDir()
	writeSegments(t, dir, 3, WriterOptions{})
	path := onlySegment(t, dir)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	second := frameOffsets(data)[1]
	data[second+frameHeaderSize+2] ^= 0xFF
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	ds := mustScan(t, dir)
	if got := seqs(ds); !reflect.DeepEqual(got, []uint64{1, 3}) {
		t.Fatalf("seqs = %v", got)
	}
	if ds.Integrity.CorruptRecords != 1 {
		t.Fatalf("integrity = %+v", ds.Integrity)
	}
	if ds.Integrity.Complete() {
		t.Fatal("must not be complete")
	}
}

func TestCorruptFrameHeaderResynchronizes(t *testing.T) {
	dir := t.TempDir()
	writeSegments(t, dir, 3, WriterOptions{})
	path := onlySegment(t, dir)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	second := frameOffsets(data)[1]
	// Damage the length field. Without resynchronizing, a wrong length would
	// misplace every following frame.
	data[second+syncSize+5] ^= 0xFF
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	ds := mustScan(t, dir)
	if got := seqs(ds); !reflect.DeepEqual(got, []uint64{1, 3}) {
		t.Fatalf("seqs = %v", got)
	}
	if ds.Integrity.CorruptRegions != 1 || ds.Integrity.CorruptBytes == 0 {
		t.Fatalf("integrity = %+v", ds.Integrity)
	}
	if ds.Integrity.CountMismatches != 1 {
		t.Fatalf("footer said 3 records but 2 were read: %+v", ds.Integrity)
	}
}

// Every single-byte change anywhere in a segment must be noticed. This is what
// makes "corruption can't pass silently" more than a claim about chosen cases.
func TestAnyByteFlipIsNeverSilent(t *testing.T) {
	src := t.TempDir()
	writeSegments(t, src, 3, WriterOptions{})
	path := onlySegment(t, src)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint64]*Record{1: recordWithSeq(1), 2: recordWithSeq(2), 3: recordWithSeq(3)}

	for i := range original {
		dir := t.TempDir()
		mutated := append([]byte(nil), original...)
		mutated[i] ^= 0x40
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(path)), mutated, 0o600); err != nil {
			t.Fatal(err)
		}
		ds, err := Scan(dir, ScanOptions{})
		if err != nil {
			continue // A fatal error is a visible failure.
		}
		if ds.Integrity.Complete() {
			t.Fatalf("flip at byte %d of %d went unnoticed", i, len(original))
		}
		for _, e := range ds.Entries {
			got, err := ds.Load(e)
			if err != nil {
				t.Fatalf("flip at %d: Load: %v", i, err)
			}
			if !reflect.DeepEqual(got, want[got.Seq]) {
				t.Fatalf("flip at %d produced an altered record: %+v", i, got)
			}
		}
		_ = ds.Close()
	}
}

func appendRawFrame(t *testing.T, dir string, payload []byte) {
	t.Helper()
	w, err := NewWriter(dir, WriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	frame := Frame{stored: payload, rawLen: uint32(len(payload)), crc: crc32.Checksum(payload, castagnoli), codec: codecNone}
	if err := w.Append(frame); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownSchemaVersionFailsClearly(t *testing.T) {
	dir := t.TempDir()
	rec := validRecord()
	rec.SchemaVersion = 99
	payload, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	appendRawFrame(t, dir, payload)

	_, err = Scan(dir, ScanOptions{})
	var unknown *UnknownVersionError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want UnknownVersionError", err)
	}
	if unknown.Version != 99 || !strings.Contains(err.Error(), "99") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnknownFormatVersionFailsClearly(t *testing.T) {
	dir := t.TempDir()
	writeSegments(t, dir, 1, WriterOptions{})
	path := onlySegment(t, dir)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(data[8:], 7)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Scan(dir, ScanOptions{})
	var unknown *UnknownVersionError
	if !errors.As(err, &unknown) || unknown.Version != 7 {
		t.Fatalf("err = %v, want UnknownVersionError{7}", err)
	}
}

func TestRecordFailingValidationIsCountedAndSkipped(t *testing.T) {
	dir := t.TempDir()
	rec := validRecord()
	rec.Request.Path = "http://evil.example/"
	payload, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	appendRawFrame(t, dir, payload)

	ds := mustScan(t, dir)
	if len(ds.Entries) != 0 || ds.Integrity.InvalidRecords != 1 || ds.Integrity.Complete() {
		t.Fatalf("entries = %d, integrity = %+v", len(ds.Entries), ds.Integrity)
	}
}

func TestUnknownRecordFieldIsInvalid(t *testing.T) {
	dir := t.TempDir()
	payload, err := json.Marshal(validRecord())
	if err != nil {
		t.Fatal(err)
	}
	payload = []byte(strings.Replace(string(payload), `{"schema_version":1,`, `{"schema_version":1,"target_url":"http://evil.example/",`, 1))
	appendRawFrame(t, dir, payload)
	ds := mustScan(t, dir)
	if len(ds.Entries) != 0 || ds.Integrity.InvalidRecords != 1 {
		t.Fatalf("entries = %d, integrity = %+v", len(ds.Entries), ds.Integrity)
	}
}

func TestOversizedFrameIsSkippedWithoutAllocating(t *testing.T) {
	dir := t.TempDir()
	writeSegments(t, dir, 3, WriterOptions{})
	ds, err := Scan(dir, ScanOptions{MaxFrameBytes: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ds.Close() }()
	if len(ds.Entries) != 0 || ds.Integrity.OversizeRecords != 3 || ds.Integrity.Complete() {
		t.Fatalf("entries = %d, integrity = %+v", len(ds.Entries), ds.Integrity)
	}
}

func TestLengthClaimingMoreThanTheFileIsATornTail(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, WriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// A frame whose checksummed header claims a payload beyond the end of file.
	header := frameHeader{kind: frameKindRecord, codec: codecZstd, storedLen: 1 << 20, rawLen: 1 << 20}
	if err := w.openSegment(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.file.Write(header.appendTo(nil, w.sync)); err != nil {
		t.Fatal(err)
	}
	if err := w.file.Close(); err != nil {
		t.Fatal(err)
	}
	ds := mustScan(t, dir)
	if ds.Integrity.PartialTails != 1 || len(ds.Entries) != 0 {
		t.Fatalf("integrity = %+v", ds.Integrity)
	}
}

func TestCompressedLengthMismatchIsCorrupt(t *testing.T) {
	// A frame with a valid checksum whose content expands past its declared
	// length, as a decompression bomb would.
	dir := t.TempDir()
	enc := newTestEncoder(t)
	frame := mustFrame(t, enc, recordWithSeq(1))
	frame.rawLen = 4
	w, err := NewWriter(dir, WriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(frame); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	ds := mustScan(t, dir)
	if len(ds.Entries) != 0 || ds.Integrity.CorruptRecords != 1 {
		t.Fatalf("entries = %d, integrity = %+v", len(ds.Entries), ds.Integrity)
	}
}

func TestMissingMiddleSegmentIsReported(t *testing.T) {
	dir := t.TempDir()
	writeSegments(t, dir, 3, WriterOptions{MaxSegmentBytes: 1})
	names := segmentFiles(t, dir)
	if err := os.Remove(filepath.Join(dir, names[1])); err != nil {
		t.Fatal(err)
	}
	ds := mustScan(t, dir)
	if ds.Integrity.MissingSegments != 1 || ds.Integrity.Complete() {
		t.Fatalf("integrity = %+v", ds.Integrity)
	}
}

func TestMissingFinalSegmentIsReported(t *testing.T) {
	dir := t.TempDir()
	writeSegments(t, dir, 3, WriterOptions{MaxSegmentBytes: 1})
	names := segmentFiles(t, dir)
	if err := os.Remove(filepath.Join(dir, names[len(names)-1])); err != nil {
		t.Fatal(err)
	}
	ds := mustScan(t, dir)
	if ds.Integrity.IncompleteRuns != 1 || ds.Integrity.Complete() {
		t.Fatalf("integrity = %+v", ds.Integrity)
	}
}

func TestDuplicateSegmentIsNotReadTwice(t *testing.T) {
	dir := t.TempDir()
	writeSegments(t, dir, 2, WriterOptions{})
	path := onlySegment(t, dir)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "copy"+SealedSuffix), data, 0o600); err != nil {
		t.Fatal(err)
	}
	ds := mustScan(t, dir)
	if len(ds.Entries) != 2 || ds.Integrity.DuplicateSegments != 1 || ds.Integrity.Complete() {
		t.Fatalf("entries = %d, integrity = %+v", len(ds.Entries), ds.Integrity)
	}
}

func TestDamagedSegmentHeaderIsReported(t *testing.T) {
	dir := t.TempDir()
	writeSegments(t, dir, 1, WriterOptions{})
	path := onlySegment(t, dir)
	if err := os.WriteFile(path, []byte("not a segment"), 0o600); err != nil {
		t.Fatal(err)
	}
	ds := mustScan(t, dir)
	if ds.Integrity.UnreadableSegments != 1 || ds.Integrity.Complete() {
		t.Fatalf("integrity = %+v", ds.Integrity)
	}
}

func TestSymlinkedSegmentIsNotFollowed(t *testing.T) {
	outside := t.TempDir()
	writeSegments(t, outside, 1, WriterOptions{})
	target := onlySegment(t, outside)

	dir := t.TempDir()
	writeSegments(t, dir, 1, WriterOptions{})
	if err := os.Symlink(target, filepath.Join(dir, "linked"+SealedSuffix)); err != nil {
		t.Fatal(err)
	}
	ds := mustScan(t, dir)
	if len(ds.Entries) != 1 || ds.Integrity.UnreadableSegments != 1 {
		t.Fatalf("entries = %d, integrity = %+v", len(ds.Entries), ds.Integrity)
	}
}

func TestRecordLimitFailsInsteadOfTruncatingSilently(t *testing.T) {
	dir := t.TempDir()
	writeSegments(t, dir, 3, WriterOptions{})
	if _, err := Scan(dir, ScanOptions{MaxRecords: 2}); !errors.Is(err, ErrTooManyRecords) {
		t.Fatalf("err = %v, want ErrTooManyRecords", err)
	}
}

func TestEntriesAreOrderedByArrivalAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	enc := newTestEncoder(t)
	base := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

	// The later run is written first, so file order alone would be wrong.
	later, err := NewWriter(dir, WriterOptions{Now: func() time.Time { return base.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	if err := later.Append(mustFrame(t, enc, recordWithSeq(1))); err != nil {
		t.Fatal(err)
	}
	if err := later.Close(); err != nil {
		t.Fatal(err)
	}
	earlier, err := NewWriter(dir, WriterOptions{Now: func() time.Time { return base }})
	if err != nil {
		t.Fatal(err)
	}
	// Completion order differs from arrival order within this run.
	for _, seq := range []uint64{3, 1, 2} {
		if err := earlier.Append(mustFrame(t, enc, recordWithSeq(seq))); err != nil {
			t.Fatal(err)
		}
	}
	if err := earlier.Close(); err != nil {
		t.Fatal(err)
	}

	ds := mustScan(t, dir)
	if got := seqs(ds); !reflect.DeepEqual(got, []uint64{1, 2, 3, 1}) {
		t.Fatalf("seqs = %v, want earlier run 1,2,3 then later run 1", got)
	}
	if ds.Entries[3].Run == ds.Entries[0].Run {
		t.Fatal("entries from different runs share a run order")
	}
}

func TestLoadDetectsFileChangedAfterScan(t *testing.T) {
	dir := t.TempDir()
	writeSegments(t, dir, 1, WriterOptions{})
	ds := mustScan(t, dir)
	path := onlySegment(t, dir)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[frameOffsets(data)[0]+frameHeaderSize] ^= 0xFF
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ds.Load(ds.Entries[0]); err == nil {
		t.Fatal("want error for changed file")
	}
}

func TestIntegrityProblemsDoNotQuoteContent(t *testing.T) {
	var i Integrity
	i.CorruptRecords = 2
	problems := i.Problems()
	if len(problems) != 1 || !strings.Contains(problems[0], "2") {
		t.Fatalf("problems = %v", problems)
	}
}
