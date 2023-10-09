package traffic

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"time"

	"github.com/klauspost/compress/zstd"
)

// Format constants. docs/traffic-format.md specifies the byte layout.
const (
	// FormatVersion is the segment container version.
	FormatVersion = 1
	// SealedSuffix marks a segment finished by a clean rotation or shutdown.
	SealedSuffix = ".rdt"
	// OpenSuffix marks a segment still being written, or abandoned by a crash
	// or an unrecoverable write error.
	OpenSuffix = ".rdt.open"
	// HardMaxFrameBytes bounds both a frame's stored and uncompressed length
	// regardless of configuration, so a reader never allocates more.
	HardMaxFrameBytes = 64 << 20
	// DefaultMaxRecordBytes is the default limit on an encoded record.
	DefaultMaxRecordBytes = 16 << 20

	syncSize          = 8
	segmentHeaderSize = 52
	frameHeaderSize   = 28

	frameKindRecord = 1
	frameKindFooter = 2

	codecNone = 0
	codecZstd = 1
)

var (
	segmentMagic = [8]byte{'R', 'D', 'T', 'R', 'A', 'F', 'F', 'C'}
	castagnoli   = crc32.MakeTable(crc32.Castagnoli)
)

// ErrRecordTooLarge means an encoded record exceeds the configured limit.
var ErrRecordTooLarge = errors.New("record exceeds size limit")

// segmentHeader is the fixed header at the start of every segment file.
type segmentHeader struct {
	formatVersion uint16
	sync          [syncSize]byte
	runID         [16]byte
	index         uint32
	created       time.Time
}

func (h *segmentHeader) marshal() []byte {
	buf := make([]byte, segmentHeaderSize)
	copy(buf, segmentMagic[:])
	binary.BigEndian.PutUint16(buf[8:], h.formatVersion)
	copy(buf[12:], h.sync[:])
	copy(buf[20:], h.runID[:])
	binary.BigEndian.PutUint32(buf[36:], h.index)
	binary.BigEndian.PutUint64(buf[40:], uint64(h.created.UnixNano())) //nolint:gosec // Round-trips as two's complement.
	binary.BigEndian.PutUint32(buf[48:], crc32.Checksum(buf[:48], castagnoli))
	return buf
}

// frameHeader precedes every frame's payload.
type frameHeader struct {
	kind      byte
	codec     byte
	storedLen uint32
	rawLen    uint32
	crc       uint32
}

func (h *frameHeader) appendTo(dst []byte, sync [syncSize]byte) []byte {
	start := len(dst)
	dst = append(dst, sync[:]...)
	dst = append(dst, h.kind, h.codec, 0, 0)
	dst = binary.BigEndian.AppendUint32(dst, h.storedLen)
	dst = binary.BigEndian.AppendUint32(dst, h.rawLen)
	dst = binary.BigEndian.AppendUint32(dst, h.crc)
	return binary.BigEndian.AppendUint32(dst, crc32.Checksum(dst[start:], castagnoli))
}

// Frame is an encoded record ready to be appended to a segment. Encoding is
// separate from writing so compression runs off the writer goroutine.
type Frame struct {
	stored []byte
	rawLen uint32
	crc    uint32
	codec  byte
}

// EncoderOptions configures an Encoder.
type EncoderOptions struct {
	// MaxRecordBytes limits the uncompressed encoded record. Zero selects
	// DefaultMaxRecordBytes. It is capped at HardMaxFrameBytes.
	MaxRecordBytes int
}

// Encoder turns records into frames. It is safe for concurrent use.
type Encoder struct {
	maxRecordBytes int
	zenc           *zstd.Encoder
}

// NewEncoder returns an Encoder. Close releases its resources.
func NewEncoder(opts EncoderOptions) (*Encoder, error) {
	limit := opts.MaxRecordBytes
	if limit <= 0 {
		limit = DefaultMaxRecordBytes
	}
	limit = min(limit, HardMaxFrameBytes)
	zenc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedFastest),
		zstd.WithSingleSegment(true),
	)
	if err != nil {
		return nil, fmt.Errorf("traffic: create compressor: %w", err)
	}
	return &Encoder{maxRecordBytes: limit, zenc: zenc}, nil
}

// Close releases the encoder's resources.
func (e *Encoder) Close() { _ = e.zenc.Close() }

// Encode validates and compresses a record. Each frame is compressed on its
// own, so a damaged frame can't affect any other.
func (e *Encoder) Encode(rec *Record) (Frame, error) {
	if err := rec.Validate(); err != nil {
		return Frame{}, err
	}
	var buf bytes.Buffer
	jsonEnc := json.NewEncoder(&buf)
	jsonEnc.SetEscapeHTML(false)
	if err := jsonEnc.Encode(rec); err != nil {
		return Frame{}, fmt.Errorf("traffic: encode record: %w", err)
	}
	if buf.Len() > e.maxRecordBytes {
		return Frame{}, ErrRecordTooLarge
	}
	stored := e.zenc.EncodeAll(buf.Bytes(), nil)
	if len(stored) > HardMaxFrameBytes {
		return Frame{}, ErrRecordTooLarge
	}
	return Frame{
		stored: stored,
		rawLen: uint32(buf.Len()), //nolint:gosec // Bounded by maxRecordBytes.
		crc:    crc32.Checksum(stored, castagnoli),
		codec:  codecZstd,
	}, nil
}

// footer is the payload of a segment's closing frame.
type footer struct {
	RecordCount int64 `json:"record_count"`
	// Final is true on the last segment of a run that shut down cleanly. Its
	// absence is how a reader detects that a run's tail is missing.
	Final bool `json:"final"`
}

func footerFrame(f footer) (Frame, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return Frame{}, fmt.Errorf("traffic: encode footer: %w", err)
	}
	return Frame{
		stored: data,
		rawLen: uint32(len(data)), //nolint:gosec // A small fixed-shape struct.
		crc:    crc32.Checksum(data, castagnoli),
		codec:  codecNone,
	}, nil
}
