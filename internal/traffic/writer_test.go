package traffic

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func newTestEncoder(t *testing.T) *Encoder {
	t.Helper()
	enc, err := NewEncoder(EncoderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(enc.Close)
	return enc
}

func recordWithSeq(seq uint64) *Record {
	rec := validRecord()
	rec.Seq = seq
	rec.ID = fmt.Sprintf("rec-%06d", seq)
	return rec
}

func mustFrame(t *testing.T, enc *Encoder, rec *Record) Frame {
	t.Helper()
	frame, err := enc.Encode(rec)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func segmentFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestWriterSealsSegmentOnClose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "traffic")
	enc := newTestEncoder(t)
	w, err := NewWriter(dir, WriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(mustFrame(t, enc, recordWithSeq(1))); err != nil {
		t.Fatal(err)
	}
	names := segmentFiles(t, dir)
	if len(names) != 1 || !strings.HasSuffix(names[0], OpenSuffix) {
		t.Fatalf("while writing, files = %v, want one %s file", names, OpenSuffix)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	names = segmentFiles(t, dir)
	if len(names) != 1 || !strings.HasSuffix(names[0], SealedSuffix) {
		t.Fatalf("after close, files = %v, want one %s file", names, SealedSuffix)
	}
}

func TestWriterUsesOwnerOnlyPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "traffic")
	enc := newTestEncoder(t)
	w, err := NewWriter(dir, WriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(mustFrame(t, enc, recordWithSeq(1))); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir perm = %o, want 700", perm)
	}
	check := func() {
		t.Helper()
		for _, name := range segmentFiles(t, dir) {
			info, err := os.Stat(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("%s perm = %o, want 600", name, perm)
			}
		}
	}
	check()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	check()
}

func TestWriterRotatesWhenSegmentIsFull(t *testing.T) {
	dir := t.TempDir()
	enc := newTestEncoder(t)
	w, err := NewWriter(dir, WriterOptions{MaxSegmentBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	for seq := uint64(1); seq <= 3; seq++ {
		if err := w.Append(mustFrame(t, enc, recordWithSeq(seq))); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	names := segmentFiles(t, dir)
	if len(names) != 3 {
		t.Fatalf("files = %v, want 3 segments", names)
	}
	for _, name := range names {
		if !strings.HasSuffix(name, SealedSuffix) {
			t.Errorf("%s was not sealed", name)
		}
	}
}

func TestWriterWithNoRecordsLeavesNoSegment(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, WriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if names := segmentFiles(t, dir); len(names) != 0 {
		t.Fatalf("files = %v", names)
	}
}

func TestAppendAfterCloseFails(t *testing.T) {
	enc := newTestEncoder(t)
	w, err := NewWriter(t.TempDir(), WriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(mustFrame(t, enc, recordWithSeq(1))); !errors.Is(err, ErrWriterClosed) {
		t.Fatalf("err = %v, want ErrWriterClosed", err)
	}
}

func TestEncodeRejectsOversizedRecord(t *testing.T) {
	enc, err := NewEncoder(EncoderOptions{MaxRecordBytes: 256})
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	rec := validRecord()
	rec.Request.Body = Body{State: BodyPresent, Data: make([]byte, 1024)}
	if _, err := enc.Encode(rec); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("err = %v, want ErrRecordTooLarge", err)
	}
}

func TestEncodeRejectsInvalidRecord(t *testing.T) {
	enc := newTestEncoder(t)
	rec := validRecord()
	rec.Request.Path = "relative"
	if _, err := enc.Encode(rec); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("err = %v, want ErrInvalidRecord", err)
	}
}

func TestEncodeIsSafeForConcurrentUse(t *testing.T) {
	enc := newTestEncoder(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 50 {
				if _, err := enc.Encode(recordWithSeq(uint64(i*1000 + j + 1))); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
}

// faultFS wraps the real file system and injects failures on chosen writes.
type faultFS struct {
	FS
	mu sync.Mutex
	// writeFault returns the bytes to really write and the error to return.
	writeFault    func(call int, p []byte) (int, error)
	truncateFault error
	writes        int
}

type faultFile struct {
	File
	fs *faultFS
}

func (f *faultFS) Create(name string) (File, error) {
	file, err := f.FS.Create(name)
	if err != nil {
		return nil, err
	}
	return &faultFile{File: file, fs: f}, nil
}

func (f *faultFile) Write(p []byte) (int, error) {
	f.fs.mu.Lock()
	f.fs.writes++
	call := f.fs.writes
	fault := f.fs.writeFault
	f.fs.mu.Unlock()
	if fault != nil {
		n, err := fault(call, p)
		if err != nil {
			written, werr := f.File.Write(p[:n])
			if werr != nil {
				return written, werr
			}
			return written, err
		}
	}
	return f.File.Write(p)
}

func (f *faultFile) Truncate(size int64) error {
	if f.fs.truncateFault != nil {
		return f.fs.truncateFault
	}
	return f.File.Truncate(size)
}

func newFaultWriter(t *testing.T, dir string, fault func(int, []byte) (int, error), truncateErr error) (*Writer, *faultFS) {
	t.Helper()
	base, err := openOSFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	ffs := &faultFS{FS: base, writeFault: fault, truncateFault: truncateErr}
	w, err := NewWriter(dir, WriterOptions{FS: ffs})
	if err != nil {
		t.Fatal(err)
	}
	return w, ffs
}

func fileSize(t *testing.T, dir string) int64 {
	t.Helper()
	names := segmentFiles(t, dir)
	if len(names) != 1 {
		t.Fatalf("files = %v, want one", names)
	}
	info, err := os.Stat(filepath.Join(dir, names[0]))
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func TestDiskFullRemovesPartialFrameAndReportsError(t *testing.T) {
	dir := t.TempDir()
	enc := newTestEncoder(t)
	failing := false
	w, _ := newFaultWriter(t, dir, func(_ int, p []byte) (int, error) {
		if failing {
			return len(p) / 2, syscall.ENOSPC
		}
		return len(p), nil
	}, nil)

	if err := w.Append(mustFrame(t, enc, recordWithSeq(1))); err != nil {
		t.Fatal(err)
	}
	good := fileSize(t, dir)

	failing = true
	err := w.Append(mustFrame(t, enc, recordWithSeq(2)))
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("err = %v, want ENOSPC", err)
	}
	if size := fileSize(t, dir); size != good {
		t.Fatalf("after failed write size = %d, want %d: partial frame left behind", size, good)
	}

	// Space frees up: the writer continues in the same segment.
	failing = false
	if err := w.Append(mustFrame(t, enc, recordWithSeq(3))); err != nil {
		t.Fatalf("append after recovery: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFailedRepairAbandonsSegmentAndStartsANewOne(t *testing.T) {
	dir := t.TempDir()
	enc := newTestEncoder(t)
	failing := false
	w, _ := newFaultWriter(t, dir, func(_ int, p []byte) (int, error) {
		if failing {
			return len(p) / 2, syscall.EIO
		}
		return len(p), nil
	}, errors.New("truncate failed"))

	if err := w.Append(mustFrame(t, enc, recordWithSeq(1))); err != nil {
		t.Fatal(err)
	}
	failing = true
	if err := w.Append(mustFrame(t, enc, recordWithSeq(2))); !errors.Is(err, syscall.EIO) {
		t.Fatalf("err = %v, want EIO", err)
	}
	failing = false
	if err := w.Append(mustFrame(t, enc, recordWithSeq(3))); err != nil {
		t.Fatalf("append after abandon: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	names := segmentFiles(t, dir)
	if len(names) != 2 {
		t.Fatalf("files = %v, want abandoned segment plus a new one", names)
	}
	var open, sealed int
	for _, name := range names {
		switch {
		case strings.HasSuffix(name, OpenSuffix):
			open++
		case strings.HasSuffix(name, SealedSuffix):
			sealed++
		}
	}
	if open != 1 || sealed != 1 {
		t.Fatalf("files = %v, want one abandoned and one sealed", names)
	}
}

func TestCreateFailureIsReturned(t *testing.T) {
	dir := t.TempDir()
	enc := newTestEncoder(t)
	base, err := openOSFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWriter(dir, WriterOptions{FS: createFailFS{FS: base}})
	if err != nil {
		t.Fatal(err)
	}
	err = w.Append(mustFrame(t, enc, recordWithSeq(1)))
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("err = %v, want permission error", err)
	}
}

type createFailFS struct{ FS }

func (createFailFS) Create(string) (File, error) { return nil, fs.ErrPermission }
