package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTakeMetadataCompatibility(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "Show_20260101_120000_ch8_48kHz.wav")
	writeTestWAV(t, file, 0, true) // mono 48 kHz, including a valid midnight reference
	if ch, hz := recordingFormat(file); ch != 1 || hz != 48000 {
		t.Fatalf("header format = %d/%d", ch, hz)
	}
	// Stage A deliberately retains the legacy name-based channel defaults.
	if got := recordingChannels(file); len(got) != 8 {
		t.Fatalf("default names = %d", len(got))
	}
	mutex.Lock()
	gotChannels := takeChannels(file)
	mutex.Unlock()
	if gotChannels != 8 {
		t.Fatalf("decoder channels = %d", gotChannels)
	}

	stamp := &recTimecode{Start: "01:00:00:00", Rate: "25", Source: "LTC", TimeReference: 48000, SampleRate: 48000}
	if err := writeSidecar(file, recChannelsFile{Timecode: stamp}, false); err != nil {
		t.Fatal(err)
	}
	if ref, _, ok := takeTimecode(file, 96000); !ok || ref != 96000 {
		t.Fatalf("sidecar precedence = %d/%v", ref, ok)
	}

	for _, invalid := range []recTimecode{
		{Rate: "invalid", TimeReference: 48000, SampleRate: 48000},
		{Rate: "25", TimeReference: 48000, SampleRate: 0},
	} {
		if err := writeSidecar(file, recChannelsFile{Timecode: &invalid}, false); err != nil {
			t.Fatal(err)
		}
		if ref, _, ok := takeTimecode(file, 96000); !ok || ref != 0 {
			t.Fatalf("midnight BWF fallback = %d/%v", ref, ok)
		}
	}

	for _, name := range []string{"renamed.wav", "Show_20261399_120000_ch8_48kHz.wav"} {
		path := filepath.Join(dir, name)
		writeTestWAV(t, path, 0, true)
		if row := buildRecordingRow(path); row.Channels != 0 {
			t.Fatalf("legacy row gate: %+v", row)
		}
		mutex.Lock()
		err := validatePlaybackFile(path)
		mutex.Unlock()
		if err != nil {
			t.Fatalf("legacy validation gate: %v", err)
		}
	}
}

func TestTakeMetadataPartialWAV(t *testing.T) {
	file := filepath.Join(t.TempDir(), "Show_20260101_120000_ch2_44kHz.wav")
	writeTestWAV(t, file, 123, true)
	full, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	// A later truncated chunk must not erase the earlier fmt facts.
	if err := os.WriteFile(file, full[:40], 0600); err != nil {
		t.Fatal(err)
	}
	if ch, hz := recordingFormat(file); ch != 1 || hz != 48000 {
		t.Fatalf("partial fmt = %d/%d", ch, hz)
	}

	// Unknown, word-padded chunks must not hide a later BWF or data chunk.
	odd := append([]byte(nil), full[:12]...)
	odd = append(odd, []byte("JUNK\x01\x00\x00\x00x\x00")...)
	odd = append(odd, full[12:]...)
	if err := os.WriteFile(file, odd, 0600); err != nil {
		t.Fatal(err)
	}
	if ref, err := wavTimeReference(file); err != nil || ref != 123 {
		t.Fatalf("padded BWF = %d/%v", ref, err)
	}

	// Active or killed WAVs retain the existing file-size estimate.
	for _, size := range []uint32{0, 0xffffffff} {
		b := append([]byte(nil), full...)
		binary.LittleEndian.PutUint32(b[len(b)-8:len(b)-4], size)
		if err := os.WriteFile(file, b, 0600); err != nil {
			t.Fatal(err)
		}
		want := time.Duration(len(b)-44) * time.Second / (48000 * 3)
		if got := recordingDuration(file, 1, 48000); got != want {
			t.Fatalf("incomplete duration = %v, want %v", got, want)
		}
	}
}

// Each old reader ignored malformed fields outside its own responsibility.
func TestTakeMetadataIndependentFields(t *testing.T) {
	file := filepath.Join(t.TempDir(), "Show_20260101_120000_ch2_44kHz.wav")
	writeTestWAV(t, file, 123, true)
	full, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range []string{"fmt ", "ds64", "bext"} {
		t.Run(chunk, func(t *testing.T) {
			b := append([]byte(nil), full[:12]...)
			b = append(b, chunk...)
			b = binary.LittleEndian.AppendUint32(b, 2)
			b = append(b, 0, 0)
			b = append(b, full[12:]...)
			if err := os.WriteFile(file, b, 0600); err != nil {
				t.Fatal(err)
			}
			ch, hz := recordingFormat(file)
			wantCh, wantHz := 1, 48000
			if chunk == "fmt " {
				wantCh, wantHz = 2, 44100
			}
			if ch != wantCh || hz != wantHz {
				t.Fatalf("format = %d/%d", ch, hz)
			}
			ref, err := wavTimeReference(file)
			if chunk == "bext" {
				if err == nil {
					t.Fatal("short BWF accepted")
				}
			} else if err != nil || ref != 123 {
				t.Fatalf("BWF = %d/%v", ref, err)
			}
			f, err := os.Open(file)
			if err != nil {
				t.Fatal(err)
			}
			got := wavDataBytes(f)
			f.Close()
			want := int64(4)
			if chunk == "ds64" {
				want = 0
			}
			if got != want {
				t.Fatalf("data = %d, want %d", got, want)
			}
		})
	}
}
