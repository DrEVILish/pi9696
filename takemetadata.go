package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// recFilenameRe also serves the legacy take-selection and listing sort rules.
var recFilenameRe = regexp.MustCompile(`^([A-Za-z0-9 -]+)_(\d{8})_(\d{6})_ch(\d+)_(\d+)kHz(-\d+)?\.(\w+)$`)

type takeFilename struct {
	Channels, SampleRate int
	Start                time.Time
	StartValid           bool
	Format               string
}

func parseTakeFilename(path string) (n takeFilename) {
	m := recFilenameRe.FindStringSubmatch(filepath.Base(path))
	if m == nil {
		return
	}
	n.Channels, _ = strconv.Atoi(m[4])
	khz, _ := strconv.Atoi(m[5])
	n.SampleRate = khz * 1000
	if n.SampleRate == 44000 {
		n.SampleRate = 44100
	}
	var err error
	n.Start, err = time.ParseInLocation("20060102 150405", m[2]+" "+m[3], time.Local)
	n.StartValid = err == nil
	n.Format = strings.ToUpper(m[7])
	return
}

type wavMetadata struct {
	Channels, SampleRate int
	DataBytes            int64
	TimeReference        int64
	TimeReferenceErr     error
}

// readWAVMetadata walks only header chunks, retaining each field even when
// another field is malformed. A nil TimeReferenceErr includes midnight.
func readWAVMetadata(r io.ReadSeeker) (m wavMetadata) {
	m.TimeReferenceErr = errors.New("no bext chunk")
	var hdr [12]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		m.TimeReferenceErr = err
		return
	}
	rf64 := string(hdr[:4]) == "RF64"
	if (!rf64 && string(hdr[:4]) != "RIFF") || string(hdr[8:]) != "WAVE" {
		m.TimeReferenceErr = errors.New("not a WAV file")
		return
	}
	var ds64Data int64
	fmtSeen, bextSeen, dataInvalid := false, false, false
	for {
		var chunk [8]byte
		if _, err := io.ReadFull(r, chunk[:]); err != nil {
			return
		}
		size := int64(binary.LittleEndian.Uint32(chunk[4:]))
		pos, err := r.Seek(0, io.SeekCurrent)
		if err != nil {
			return
		}
		next := pos + size + size%2
		switch string(chunk[:4]) {
		case "fmt ":
			if !fmtSeen {
				fmtSeen = true
				var f [16]byte
				if size >= 16 {
					if _, err := io.ReadFull(r, f[:]); err == nil {
						ch, hz := int(binary.LittleEndian.Uint16(f[2:4])), int(binary.LittleEndian.Uint32(f[4:8]))
						if ch > 0 && hz > 0 {
							m.Channels, m.SampleRate = ch, hz
						}
					}
				}
			}
		case "ds64":
			var ds [16]byte
			if size < 16 {
				dataInvalid = true
			} else if _, err := io.ReadFull(r, ds[:]); err != nil {
				dataInvalid = true
			} else {
				ds64Data = int64(binary.LittleEndian.Uint64(ds[8:]))
			}
		case "bext":
			if !bextSeen {
				bextSeen = true
				var b [346]byte
				if size < int64(len(b)) {
					m.TimeReferenceErr = errors.New("short bext chunk")
				} else if _, err := io.ReadFull(r, b[:]); err != nil {
					m.TimeReferenceErr = err
				} else {
					m.TimeReference = int64(binary.LittleEndian.Uint64(b[338:]))
					m.TimeReferenceErr = nil
				}
			}
		case "data":
			if !dataInvalid {
				m.DataBytes = size
				if rf64 && size == 0xffffffff {
					m.DataBytes = ds64Data
				}
			}
			return
		}
		if _, err := r.Seek(next, io.SeekStart); err != nil {
			return
		}
	}
}

type takeMetadata struct {
	Channels, SampleRate int
	Duration             time.Duration
	ChannelNames         []recChannel
	Sidecar              recChannelsFile
	Filename             takeFilename
	WAV                  wavMetadata
	fileSize             int64
	statOK               bool
	sidecarErr           error
}

// readTakeMetadata reads the filename, WAV and sidecar once per resolution.
// Missing or incomplete sources do not discard facts from the others.
func readTakeMetadata(path string) (m takeMetadata) {
	m.Filename = parseTakeFilename(path)
	m.Channels, m.SampleRate = m.Filename.Channels, m.Filename.SampleRate
	if info, err := os.Stat(path); err == nil {
		m.fileSize, m.statOK = info.Size(), true
	}
	if f, err := os.Open(path); err == nil {
		m.WAV = readWAVMetadata(f)
		f.Close()
	} else {
		m.WAV.TimeReferenceErr = err
	}
	if m.WAV.Channels > 0 && m.WAV.SampleRate > 0 {
		m.Channels, m.SampleRate = m.WAV.Channels, m.WAV.SampleRate
	}
	m.Sidecar, m.sidecarErr = readRecordingSidecar(path)
	if m.sidecarErr == nil {
		m.ChannelNames = m.Sidecar.Channels
	}
	if len(m.ChannelNames) > 0 {
		sort.Slice(m.ChannelNames, func(i, j int) bool { return m.ChannelNames[i].Number < m.ChannelNames[j].Number })
	} else {
		// Stage A retains filename-based defaults; header consistency is a separate fix.
		m.ChannelNames = make([]recChannel, m.Filename.Channels)
		for i := range m.ChannelNames {
			m.ChannelNames[i] = recChannel{Number: i + 1, Name: fmt.Sprintf("Ch %d", i+1)}
		}
	}
	m.Duration = m.duration(m.Channels, m.SampleRate)
	return
}

func (m takeMetadata) duration(channels, sampleRate int) time.Duration {
	if !m.statOK {
		return 0
	}
	return metadataDuration(m.fileSize, m.WAV.DataBytes, channels, sampleRate)
}

func (m takeMetadata) timecodeAtRate(sampleRate, fallbackRate int) (int64, int, bool) {
	if t := m.Sidecar.Timecode; m.sidecarErr == nil && t != nil {
		if rate := t.rateIndex(); rate >= 0 && t.SampleRate > 0 {
			return t.TimeReference * int64(sampleRate) / int64(t.SampleRate), rate, true
		}
	}
	if m.WAV.TimeReferenceErr == nil {
		return m.WAV.TimeReference, fallbackRate, true
	}
	return 0, fallbackRate, false
}

// Compatibility entry points share the parser and resolution rules.
func recordingFormat(path string) (channels, rate int) {
	m := readTakeMetadata(path)
	return m.Channels, m.SampleRate
}

func recordingDuration(path string, channels, sampleRate int) time.Duration {
	return readTakeMetadata(path).duration(channels, sampleRate)
}

func wavDataBytes(r io.ReadSeeker) int64 { return readWAVMetadata(r).DataBytes }

func wavTimeReference(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	m := readWAVMetadata(f)
	return m.TimeReference, m.TimeReferenceErr
}

func metadataDuration(fileSize, dataBytes int64, channels, sampleRate int) time.Duration {
	const bytesPerSample = 3 // pcm_s24le
	if dataBytes <= 0 || dataBytes > fileSize-12 {
		dataBytes = fileSize - 44
	}
	bytesPerSec := int64(channels) * int64(bytesPerSample) * int64(sampleRate)
	if dataBytes <= 0 || bytesPerSec <= 0 {
		return 0
	}
	// Divide before scaling to nanoseconds: time.Duration(dataBytes) *
	// time.Second overflows int64 past ~9.2 GiB (reached in ~2 min at
	// 128ch/192kHz), going negative and poisoning seeks, demo end timers
	// and the UI.
	secs := dataBytes / bytesPerSec
	// Saturate instead of overflowing: beyond ~136 years the exact value is
	// meaningless to every caller (UI, seeks, timers).
	const maxSecs = int64(1 << 32)
	if secs > maxSecs {
		return time.Duration(maxSecs) * time.Second
	}
	rem := dataBytes % bytesPerSec
	// rem < bytesPerSec, so rem*time.Second stays in int64 for any rate a
	// real stream can have; absurd rates skip the sub-second part they
	// cannot meaningfully have anyway.
	if bytesPerSec < int64(9e9) {
		return time.Duration(secs)*time.Second + time.Duration(rem)*time.Second/time.Duration(bytesPerSec)
	}
	return time.Duration(secs) * time.Second
}
