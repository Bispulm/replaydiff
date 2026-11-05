package traffic

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

const (
	// DefaultMaxRecords bounds the in-memory index built by Scan.
	DefaultMaxRecords = 1_000_000

	maxFooterBytes = 4 << 10
	syncScanChunk  = 1 << 20
)

// Errors returned by Scan and Load.
var (
	// ErrNoSegments means the directory holds no segment files. A dataset with
	// nothing in it is an error, because it can't be evidence of anything.
	ErrNoSegments = errors.New("no traffic segments found")
	// ErrTooManyRecords means the dataset exceeds ScanOptions.MaxRecords. Scan
	// fails rather than silently replaying a prefix.
	ErrTooManyRecords = errors.New("dataset exceeds record limit")
	// ErrRecordChanged means a segment no longer matches what Scan read.
	ErrRecordChanged = errors.New("record changed since scan")
)

// UnknownVersionError means a segment or record uses a version this build
// doesn't understand.
type UnknownVersionError struct {
	Kind    string
	Version int
}

func (e *UnknownVersionError) Error() string {
	return fmt.Sprintf("unknown traffic %s version %d: this build reads version %d", e.Kind, e.Version, e.supported())
}

func (e *UnknownVersionError) supported() int {
	if e.Kind == "format" {
		return FormatVersion
	}
	return SchemaVersion
}

// Integrity reports everything Scan couldn't read or vouch for. A non-zero
// field means evidence is missing, so it must reach the report.
type Integrity struct {
	Segments           int   `json:"segments"`
	Records            int   `json:"records"`
	UnsealedSegments   int   `json:"unsealed_segments,omitempty"`
	UnreadableSegments int   `json:"unreadable_segments,omitempty"`
	DuplicateSegments  int   `json:"duplicate_segments,omitempty"`
	MissingSegments    int   `json:"missing_segments,omitempty"`
	IncompleteRuns     int   `json:"incomplete_runs,omitempty"`
	PartialTails       int   `json:"partial_tails,omitempty"`
	CorruptRegions     int   `json:"corrupt_regions,omitempty"`
	CorruptBytes       int64 `json:"corrupt_bytes,omitempty"`
	CorruptRecords     int   `json:"corrupt_records,omitempty"`
	CorruptFooters     int   `json:"corrupt_footers,omitempty"`
	InvalidRecords     int   `json:"invalid_records,omitempty"`
	OversizeRecords    int   `json:"oversize_records,omitempty"`
	DuplicateRecords   int   `json:"duplicate_records,omitempty"`
	CountMismatches    int   `json:"count_mismatches,omitempty"`
}

// Complete reports whether every segment was read in full with nothing
// skipped, damaged or missing.
func (i Integrity) Complete() bool { return len(i.Problems()) == 0 }

// Problems lists each kind of damage found, in a fixed order.
func (i Integrity) Problems() []string {
	var out []string
	add := func(n int, what string) {
		if n > 0 {
			out = append(out, fmt.Sprintf("%d %s", n, what))
		}
	}
	add(i.UnsealedSegments, "unsealed segment(s), the writer did not finish cleanly")
	add(i.UnreadableSegments, "unreadable segment(s)")
	add(i.DuplicateSegments, "duplicate segment(s) ignored")
	add(i.MissingSegments, "missing segment(s)")
	add(i.IncompleteRuns, "capture run(s) with no end-of-run marker")
	add(i.PartialTails, "partial final record(s)")
	add(i.CorruptRegions, "corrupt region(s) skipped")
	add(i.CorruptRecords, "corrupt record(s) skipped")
	add(i.CorruptFooters, "corrupt segment footer(s)")
	add(i.InvalidRecords, "invalid record(s) skipped")
	add(i.OversizeRecords, "oversized record(s) skipped")
	add(i.DuplicateRecords, "duplicate record(s) ignored")
	add(i.CountMismatches, "segment(s) whose record count disagrees with the footer")
	return out
}

// Entry indexes one readable record without keeping its bodies in memory.
type Entry struct {
	// Run orders capture runs by start time.
	Run        int
	Seq        uint64
	ID         string
	SessionKey string
	Protocol   Protocol
	Method     string
	RPC        string
	BodyState  BodyState
	Replay     ReplayInfo
	// DescriptorDigest identifies the schema a gRPC record was sanitized with.
	DescriptorDigest string

	segment int
	offset  int64
	header  frameHeader
}

// ScanOptions configures Scan.
type ScanOptions struct {
	// MaxRecords limits the index size. Zero selects DefaultMaxRecords.
	MaxRecords int
	// MaxFrameBytes limits a record frame's stored and uncompressed sizes.
	// Zero selects HardMaxFrameBytes, which is also the upper bound.
	MaxFrameBytes int64
}

// Dataset is a validated index over a directory of segments. Scan reads and
// checks everything up front, so damage and unknown versions surface before
// any traffic is sent, and bodies are loaded only when needed.
type Dataset struct {
	// Entries lists readable records by run, then arrival order.
	Entries []Entry
	// Integrity reports what couldn't be read.
	Integrity Integrity
	// CaptureDrops counts exchanges that capture never recorded, by reason,
	// summed across runs. These records are absent, not damaged, so this doesn't
	// affect Integrity, but a report must still show the gap in coverage.
	CaptureDrops map[string]int64

	root     *os.Root
	dec      *zstd.Decoder
	segments []segmentInfo
	maxFrame int64
}

type segmentInfo struct {
	name   string
	sync   [syncSize]byte
	runID  [16]byte
	index  uint32
	create time.Time
}

// Close releases the dataset's resources.
func (d *Dataset) Close() error {
	d.dec.Close()
	return d.root.Close()
}

// Load reads one record, verifying it again because the file may have changed
// since Scan.
func (d *Dataset) Load(e Entry) (*Record, error) {
	info := d.segments[e.segment]
	file, err := d.root.Open(info.name)
	if err != nil {
		return nil, fmt.Errorf("traffic: open segment: %w", err)
	}
	defer func() { _ = file.Close() }()

	buf := make([]byte, frameHeaderSize+int64(e.header.storedLen))
	if _, err := file.ReadAt(buf, e.offset); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrRecordChanged, "short read")
	}
	header, ok := parseFrameHeader(buf[:frameHeaderSize], info.sync)
	if !ok || header != e.header {
		return nil, fmt.Errorf("%w: %s", ErrRecordChanged, "frame header differs")
	}
	rec, status, err := d.decodeRecord(header, buf[frameHeaderSize:])
	if err != nil {
		return nil, err
	}
	if status != decodeOK || rec.Seq != e.Seq {
		return nil, fmt.Errorf("%w: %s", ErrRecordChanged, "record content differs")
	}
	return rec, nil
}

type decodeStatus int

const (
	decodeOK decodeStatus = iota
	decodeCorrupt
	decodeInvalid
)

// decodeRecord verifies and parses a record frame. Its error is non-nil only
// for an unknown schema version, which must stop the whole read.
func (d *Dataset) decodeRecord(h frameHeader, stored []byte) (*Record, decodeStatus, error) {
	raw, ok := d.decompress(h, stored, d.maxFrame)
	if !ok {
		return nil, decodeCorrupt, nil
	}
	var probe struct {
		SchemaVersion *int `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil || probe.SchemaVersion == nil {
		return nil, decodeInvalid, nil //nolint:nilerr // Reported as a counter; parser text may quote content.
	}
	if *probe.SchemaVersion != SchemaVersion {
		return nil, decodeInvalid, &UnknownVersionError{Kind: "schema", Version: *probe.SchemaVersion}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var rec Record
	if err := dec.Decode(&rec); err != nil {
		return nil, decodeInvalid, nil //nolint:nilerr // As above.
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, decodeInvalid, nil //nolint:nilerr // Trailing data means the frame isn't one record.
	}
	if err := rec.Validate(); err != nil {
		return nil, decodeInvalid, nil //nolint:nilerr // Reported as a counter.
	}
	return &rec, decodeOK, nil
}

// decompress checks the payload checksum and decompresses it. The declared
// size is checked against the limit before any allocation, and the output must
// match it exactly. A checksum doesn't make a size trustworthy, because whoever
// crafts a file can compute valid ones.
func (d *Dataset) decompress(h frameHeader, stored []byte, maxRaw int64) ([]byte, bool) {
	if int64(h.rawLen) > maxRaw || crc32.Checksum(stored, castagnoli) != h.crc {
		return nil, false
	}
	switch h.codec {
	case codecNone:
		return stored, h.rawLen == h.storedLen
	case codecZstd:
		raw, err := d.dec.DecodeAll(stored, make([]byte, 0, h.rawLen))
		if err != nil || int64(len(raw)) != int64(h.rawLen) {
			return nil, false
		}
		return raw, true
	default:
		return nil, false
	}
}

func parseFrameHeader(buf []byte, sync [syncSize]byte) (frameHeader, bool) {
	if !bytes.Equal(buf[:syncSize], sync[:]) {
		return frameHeader{}, false
	}
	if crc32.Checksum(buf[:frameHeaderSize-4], castagnoli) != binary.BigEndian.Uint32(buf[frameHeaderSize-4:]) {
		return frameHeader{}, false
	}
	return frameHeader{
		kind:      buf[8],
		codec:     buf[9],
		storedLen: binary.BigEndian.Uint32(buf[12:]),
		rawLen:    binary.BigEndian.Uint32(buf[16:]),
		crc:       binary.BigEndian.Uint32(buf[20:]),
	}, true
}

// Scan validates every segment in dir and builds an index. Recoverable damage
// is recorded in Dataset.Integrity. Unknown versions, an empty dataset, and
// exceeding MaxRecords are returned as errors.
func Scan(dir string, opts ScanOptions) (*Dataset, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("traffic: open directory: %w", err)
	}
	ds, err := scan(root, opts)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return ds, nil
}

func scan(root *os.Root, opts ScanOptions) (*Dataset, error) {
	maxRecords := opts.MaxRecords
	if maxRecords <= 0 {
		maxRecords = DefaultMaxRecords
	}
	maxFrame := opts.MaxFrameBytes
	if maxFrame <= 0 || maxFrame > HardMaxFrameBytes {
		maxFrame = HardMaxFrameBytes
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(HardMaxFrameBytes), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, fmt.Errorf("traffic: create decompressor: %w", err)
	}
	ds := &Dataset{root: root, dec: dec, maxFrame: maxFrame}
	s := &scanner{ds: ds, maxRecords: maxRecords, runs: make(map[[16]byte]*runInfo)}
	if err := s.scanAll(); err != nil {
		dec.Close()
		return nil, err
	}
	return ds, nil
}

type runInfo struct {
	first   time.Time
	indexes map[uint32]bool
	final   bool
	order   int
}

type scanner struct {
	ds         *Dataset
	maxRecords int
	runs       map[[16]byte]*runInfo
}

func (s *scanner) scanAll() error {
	dir, err := s.ds.root.Open(".")
	if err != nil {
		return fmt.Errorf("traffic: open directory: %w", err)
	}
	listing, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return fmt.Errorf("traffic: list directory: %w", err)
	}

	segments := 0
	for _, item := range listing {
		name := item.Name()
		if !strings.HasSuffix(name, SealedSuffix) && !strings.HasSuffix(name, OpenSuffix) {
			continue
		}
		segments++
		s.ds.Integrity.Segments++
		// Only regular files are read, so a planted symlink can't point the
		// reader at some other file.
		if !item.Type().IsRegular() {
			s.ds.Integrity.UnreadableSegments++
			continue
		}
		if err := s.scanSegment(name); err != nil {
			return err
		}
	}
	if segments == 0 {
		return ErrNoSegments
	}
	s.finish()
	return nil
}

func (s *scanner) finish() {
	in := &s.ds.Integrity
	type runKey struct {
		id   [16]byte
		info *runInfo
	}
	ordered := make([]runKey, 0, len(s.runs))
	for id, info := range s.runs {
		ordered = append(ordered, runKey{id, info})
		if !info.final {
			in.IncompleteRuns++
		}
		var highest uint32
		for index := range info.indexes {
			highest = max(highest, index)
		}
		if missing := int(highest) + 1 - len(info.indexes); missing > 0 {
			in.MissingSegments += missing
		}
	}
	slices.SortFunc(ordered, func(a, b runKey) int {
		if c := a.info.first.Compare(b.info.first); c != 0 {
			return c
		}
		return bytes.Compare(a.id[:], b.id[:])
	})
	for i, run := range ordered {
		run.info.order = i
	}
	for i := range s.ds.Entries {
		e := &s.ds.Entries[i]
		e.Run = s.runs[s.ds.segments[e.segment].runID].order
	}
	slices.SortFunc(s.ds.Entries, func(a, b Entry) int {
		return cmp.Or(cmp.Compare(a.Run, b.Run), cmp.Compare(a.Seq, b.Seq), cmp.Compare(a.segment, b.segment), cmp.Compare(a.offset, b.offset))
	})
	s.ds.Entries = slices.CompactFunc(s.ds.Entries, func(a, b Entry) bool {
		if a.Run == b.Run && a.Seq == b.Seq {
			in.DuplicateRecords++
			return true
		}
		return false
	})
	in.Records = len(s.ds.Entries)
}

func (s *scanner) scanSegment(name string) error {
	in := &s.ds.Integrity
	file, err := s.ds.root.Open(name)
	if err != nil {
		in.UnreadableSegments++
		return nil //nolint:nilerr // Counted; the rest of the dataset is still read.
	}
	defer func() { _ = file.Close() }()
	stat, err := file.Stat()
	if err != nil {
		in.UnreadableSegments++
		return nil //nolint:nilerr // As above.
	}

	var buf [segmentHeaderSize]byte
	if _, err := io.ReadFull(file, buf[:]); err != nil {
		in.UnreadableSegments++
		return nil //nolint:nilerr // As above.
	}
	info, version, ok := parseSegmentHeader(buf[:])
	if version != 0 && version != FormatVersion {
		return &UnknownVersionError{Kind: "format", Version: version}
	}
	if !ok {
		in.UnreadableSegments++
		return nil
	}
	info.name = name

	run := s.runs[info.runID]
	if run == nil {
		run = &runInfo{first: info.create, indexes: make(map[uint32]bool)}
		s.runs[info.runID] = run
	}
	if run.indexes[info.index] {
		in.DuplicateSegments++
		return nil
	}
	run.indexes[info.index] = true
	if info.create.Before(run.first) {
		run.first = info.create
	}

	s.ds.segments = append(s.ds.segments, info)
	return s.walkFrames(file, stat.Size(), info, len(s.ds.segments)-1, run)
}

// parseSegmentHeader returns the format version whenever the magic matches,
// even if the rest of the header fails its checksum: a future version may lay
// the header out differently.
func parseSegmentHeader(buf []byte) (segmentInfo, int, bool) {
	if !bytes.Equal(buf[:len(segmentMagic)], segmentMagic[:]) {
		return segmentInfo{}, 0, false
	}
	version := int(binary.BigEndian.Uint16(buf[8:]))
	if crc32.Checksum(buf[:48], castagnoli) != binary.BigEndian.Uint32(buf[48:]) {
		return segmentInfo{}, version, false
	}
	var info segmentInfo
	copy(info.sync[:], buf[12:])
	copy(info.runID[:], buf[20:])
	info.index = binary.BigEndian.Uint32(buf[36:])
	info.create = time.Unix(0, int64(binary.BigEndian.Uint64(buf[40:])))
	return info, version, true
}

func (s *scanner) walkFrames(file io.ReaderAt, size int64, info segmentInfo, segment int, run *runInfo) error {
	in := &s.ds.Integrity
	var (
		off        int64 = segmentHeaderSize
		headerBuf  [frameHeaderSize]byte
		seen       int64
		sawFooter  bool
		footerRead footer
		finder     = syncFinder{file: file, size: size, marker: info.sync}
	)
	for off < size {
		if sawFooter {
			in.CorruptRegions++
			in.CorruptBytes += size - off
			break
		}
		if size-off < frameHeaderSize {
			in.PartialTails++
			break
		}
		if _, err := file.ReadAt(headerBuf[:], off); err != nil {
			in.PartialTails++
			break
		}
		header, ok := parseFrameHeader(headerBuf[:], info.sync)
		if !ok {
			next := finder.next(off + 1)
			in.CorruptRegions++
			if next < 0 {
				in.CorruptBytes += size - off
				break
			}
			in.CorruptBytes += next - off
			off = next
			continue
		}
		end := off + frameHeaderSize + int64(header.storedLen)
		if end > size {
			in.PartialTails++
			break
		}

		switch header.kind {
		case frameKindFooter:
			if f, ok := s.readFooter(file, off, header); ok {
				sawFooter, footerRead = true, f
			} else {
				in.CorruptFooters++
			}
		case frameKindRecord:
			seen++
			if err := s.readRecord(file, off, header, segment); err != nil {
				return err
			}
		default:
			in.CorruptRecords++
		}
		off = end
	}

	if !sawFooter {
		in.UnsealedSegments++
		return nil
	}
	if footerRead.RecordCount != seen {
		in.CountMismatches++
	}
	if footerRead.Final {
		run.final = true
	}
	for reason, n := range footerRead.Drops {
		if s.ds.CaptureDrops == nil {
			s.ds.CaptureDrops = make(map[string]int64)
		}
		s.ds.CaptureDrops[reason] += n
	}
	return nil
}

func (s *scanner) readFooter(file io.ReaderAt, off int64, header frameHeader) (footer, bool) {
	var f footer
	if header.storedLen > maxFooterBytes {
		return f, false
	}
	payload := make([]byte, header.storedLen)
	if _, err := file.ReadAt(payload, off+frameHeaderSize); err != nil {
		return f, false
	}
	raw, ok := s.ds.decompress(header, payload, maxFooterBytes)
	if !ok || json.Unmarshal(raw, &f) != nil {
		return f, false
	}
	return f, true
}

func (s *scanner) readRecord(file io.ReaderAt, off int64, header frameHeader, segment int) error {
	in := &s.ds.Integrity
	if int64(header.storedLen) > s.ds.maxFrame || int64(header.rawLen) > s.ds.maxFrame {
		in.OversizeRecords++
		return nil
	}
	payload := make([]byte, header.storedLen)
	if _, err := file.ReadAt(payload, off+frameHeaderSize); err != nil {
		in.CorruptRecords++
		return nil //nolint:nilerr // Counted; later frames may still be readable.
	}
	rec, status, err := s.ds.decodeRecord(header, payload)
	if err != nil {
		return err
	}
	switch status {
	case decodeCorrupt:
		in.CorruptRecords++
		return nil
	case decodeInvalid:
		in.InvalidRecords++
		return nil
	case decodeOK:
	}
	if len(s.ds.Entries) >= s.maxRecords {
		return ErrTooManyRecords
	}
	digest := ""
	if rec.Descriptor != nil {
		digest = rec.Descriptor.SetDigest
	}
	s.ds.Entries = append(s.ds.Entries, Entry{
		DescriptorDigest: digest,
		Seq:              rec.Seq,
		ID:               rec.ID,
		SessionKey:       rec.SessionKey,
		Protocol:         rec.Protocol,
		Method:           rec.Request.Method,
		RPC:              rec.RPC,
		BodyState:        rec.Request.Body.State,
		Replay:           rec.Replay,
		segment:          segment,
		offset:           off,
		header:           header,
	})
	return nil
}

// syncFinder locates sync markers after damage. The marker is random per segment,
// so content inside a record written by capture can't forge a frame boundary.
//
// A handcrafted file can repeat its own marker everywhere, so the finder keeps a
// window and only moves forward. A whole segment costs one buffer and one pass, no
// matter how many false markers it holds.
type syncFinder struct {
	file   io.ReaderAt
	size   int64
	marker [syncSize]byte
	buf    []byte
	start  int64
	end    int64
}

// next returns the offset of the first marker at or after from, or -1.
func (f *syncFinder) next(from int64) int64 {
	for from+syncSize <= f.size {
		if from < f.start || from+syncSize > f.end {
			if !f.fill(from) {
				return -1
			}
		}
		if i := bytes.Index(f.buf[from-f.start:f.end-f.start], f.marker[:]); i >= 0 {
			return from + int64(i)
		}
		// Keep enough of the tail to find a marker spanning the window's edge.
		from = f.end - (syncSize - 1)
	}
	return -1
}

func (f *syncFinder) fill(from int64) bool {
	if f.buf == nil {
		f.buf = make([]byte, syncScanChunk)
	}
	n, _ := f.file.ReadAt(f.buf, from)
	f.start, f.end = from, from+int64(n)
	return n >= syncSize
}
