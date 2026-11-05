package traffic

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"
)

// DefaultMaxSegmentBytes is the default rotation threshold.
const DefaultMaxSegmentBytes = 64 << 20

// ErrWriterClosed is returned by Append after Close.
var ErrWriterClosed = errors.New("traffic writer closed")

// File is the subset of *os.File the writer needs.
type File interface {
	Write(p []byte) (int, error)
	Sync() error
	Truncate(size int64) error
	Seek(offset int64, whence int) (int64, error)
	Close() error
}

// FS is the storage the writer uses. It exists so tests can inject failures
// such as a full disk.
type FS interface {
	Create(name string) (File, error)
	Rename(oldName, newName string) error
	SyncDir() error
}

// osFS confines all file operations to a directory.
type osFS struct{ root *os.Root }

// OpenDirFS returns the FS writers use by default, confined to dir, which is
// created if needed.
func OpenDirFS(dir string) (FS, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("traffic: create directory: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("traffic: open directory: %w", err)
	}
	return &osFS{root: root}, nil
}

// Create makes a new file readable only by its owner. O_EXCL means an existing
// file, including a planted symlink, is an error rather than a write target.
func (f *osFS) Create(name string) (File, error) {
	return f.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

func (f *osFS) Rename(oldName, newName string) error { return f.root.Rename(oldName, newName) }

func (f *osFS) SyncDir() error {
	dir, err := f.root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

// WriterOptions configures a Writer.
type WriterOptions struct {
	// MaxSegmentBytes is the size at which a segment is rotated. Zero selects
	// DefaultMaxSegmentBytes.
	MaxSegmentBytes int64
	// FS overrides the storage. Nil uses the directory given to NewWriter.
	FS FS
	// Now overrides the clock.
	Now func() time.Time
}

// Writer appends frames to rotating segment files. It isn't safe for
// concurrent use: capture owns one from a single goroutine.
type Writer struct {
	fs       FS
	maxBytes int64
	now      func() time.Time
	runID    [16]byte
	sync     [syncSize]byte

	file     File
	name     string
	offset   int64
	count    int64
	index    uint32
	started  bool
	closed   bool
	frameBuf []byte
}

// NewWriter creates dir if needed and returns a Writer for a new capture run.
// Segment files are created on the first Append.
func NewWriter(dir string, opts WriterOptions) (*Writer, error) {
	w := &Writer{fs: opts.FS, maxBytes: opts.MaxSegmentBytes, now: opts.Now}
	if w.fs == nil {
		fsys, err := OpenDirFS(dir)
		if err != nil {
			return nil, err
		}
		w.fs = fsys
	}
	if w.maxBytes <= 0 {
		w.maxBytes = DefaultMaxSegmentBytes
	}
	if w.now == nil {
		w.now = time.Now
	}
	if _, err := rand.Read(w.runID[:]); err != nil {
		return nil, fmt.Errorf("traffic: generate run id: %w", err)
	}
	return w, nil
}

// Append writes a frame, rotating first if the current segment is full. On a
// write error the partial frame is removed if possible. If that also fails the
// segment is abandoned, unsealed, and the next Append starts a new one, so a
// reader sees the damage instead of an unexplained gap.
func (w *Writer) Append(frame Frame) error {
	if w.closed {
		return ErrWriterClosed
	}
	if w.file != nil && w.offset >= w.maxBytes {
		// A failed seal doesn't lose the record being appended. The old
		// segment stays unsealed, which readers report.
		_ = w.seal(footer{})
	}
	if w.file == nil {
		if err := w.openSegment(); err != nil {
			return err
		}
	}
	if err := w.writeFrame(frameKindRecord, frame); err != nil {
		return err
	}
	w.count++
	return nil
}

// Sync flushes the current segment to stable storage.
func (w *Writer) Sync() error {
	if w.file == nil {
		return nil
	}
	return w.file.Sync()
}

// Close seals the current segment and marks it as the end of the run. A run
// that wrote nothing leaves no files.
func (w *Writer) Close() error { return w.CloseWithDrops(nil) }

// CloseWithDrops is Close, also recording how many exchanges the capture
// process dropped, by reason. If anything was dropped, a segment is written
// even for a run with no records, so the loss stays visible.
func (w *Writer) CloseWithDrops(drops map[string]int64) error {
	if w.closed {
		return nil
	}
	w.closed = true
	if w.file == nil {
		if !w.started && len(drops) == 0 {
			return nil
		}
		// The previous segment was rotated or abandoned, or nothing was
		// written, so an empty segment carries the end-of-run marker.
		if err := w.openSegment(); err != nil {
			return err
		}
	}
	return w.seal(footer{Final: true, Drops: drops})
}

func (w *Writer) openSegment() error {
	var header segmentHeader
	if _, err := rand.Read(header.sync[:]); err != nil {
		return fmt.Errorf("traffic: generate sync marker: %w", err)
	}
	header.formatVersion = FormatVersion
	header.runID = w.runID
	header.index = w.index
	header.created = w.now()

	name := fmt.Sprintf("%s-%06d", hex.EncodeToString(w.runID[:]), w.index)
	file, err := w.fs.Create(name + OpenSuffix)
	if err != nil {
		return fmt.Errorf("traffic: create segment: %w", err)
	}
	// The name is used up as soon as the file exists, even if the header write
	// below fails, because Create refuses to reuse it.
	w.index++
	w.started = true
	data := header.marshal()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("traffic: write segment header: %w", err)
	}
	w.file = file
	w.name = name
	w.sync = header.sync
	w.offset = int64(len(data))
	w.count = 0
	return nil
}

func (w *Writer) writeFrame(kind byte, frame Frame) error {
	header := frameHeader{
		kind:      kind,
		codec:     frame.codec,
		storedLen: uint32(len(frame.stored)),
		rawLen:    frame.rawLen,
		crc:       frame.crc,
	}
	w.frameBuf = header.appendTo(w.frameBuf[:0], w.sync)
	w.frameBuf = append(w.frameBuf, frame.stored...)
	n, err := w.file.Write(w.frameBuf)
	if err != nil {
		if n > 0 && !w.repair() {
			w.abandon()
		}
		return fmt.Errorf("traffic: write frame: %w", err)
	}
	w.offset += int64(n)
	return nil
}

// repair removes a partially written frame. It reports whether the file is
// positioned at the end of the last good frame.
func (w *Writer) repair() bool {
	if err := w.file.Truncate(w.offset); err != nil {
		return false
	}
	_, err := w.file.Seek(w.offset, 0)
	return err == nil
}

func (w *Writer) abandon() {
	_ = w.file.Close()
	w.file = nil
}

func (w *Writer) seal(f footer) error {
	f.RecordCount = w.count
	frame, err := footerFrame(f)
	if err != nil {
		w.abandon()
		return err
	}
	if err := w.writeFrame(frameKindFooter, frame); err != nil {
		if w.file != nil {
			w.abandon()
		}
		return fmt.Errorf("traffic: seal segment: %w", err)
	}
	if err := w.file.Sync(); err != nil {
		w.abandon()
		return fmt.Errorf("traffic: sync segment: %w", err)
	}
	if err := w.file.Close(); err != nil {
		w.file = nil
		return fmt.Errorf("traffic: close segment: %w", err)
	}
	w.file = nil
	if err := w.fs.Rename(w.name+OpenSuffix, w.name+SealedSuffix); err != nil {
		return fmt.Errorf("traffic: rename segment: %w", err)
	}
	if err := w.fs.SyncDir(); err != nil {
		return fmt.Errorf("traffic: sync directory: %w", err)
	}
	return nil
}
