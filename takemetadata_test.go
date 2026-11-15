package main

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	// Default names and playback channels follow the WAV header, not a stale name.
	if got := recordingChannels(file); len(got) != 1 {
		t.Fatalf("default names = %d", len(got))
	}
	mutex.Lock()
	gotChannels := takeChannels(file)
	mutex.Unlock()
	if gotChannels != 1 {
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

func TestTakeChannelsFollowWAVHeader(t *testing.T) {
	initTestHardware(t)
	file := filepath.Join(t.TempDir(), "Show_20260101_120000_ch8_48kHz.wav")
	makeWAV := exec.Command("ffmpeg", "-v", "error", "-f", "lavfi", "-i", "anullsrc=r=48000:cl=stereo", "-t", "1", "-c:a", "pcm_s24le", "-rf64", "always", file)
	if out, err := makeWAV.CombinedOutput(); err != nil {
		t.Fatalf("create stereo WAV: %v %s", err, out)
	}

	mutex.Lock()
	oldRate, oldChannels := sampleRateIdx, channelCount
	sampleRateIdx, channelCount = 1, 2
	mutex.Unlock()
	t.Cleanup(func() {
		mutex.Lock()
		sampleRateIdx, channelCount = oldRate, oldChannels
		mutex.Unlock()
	})
	mutex.Lock()
	validationErr := validatePlaybackFile(file)
	channels := takeChannels(file)
	playout := playoutFor(file, 0)
	cmd, pipe, err := dantePlaybackCmdFor(file, 0)
	mutex.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	if validationErr != nil {
		t.Errorf("header-matching take refused: %v", validationErr)
	}
	if channels != 2 {
		t.Errorf("take channels = %d, want 2", channels)
	}
	if playout.fileChannels != 2 {
		t.Errorf("pump channels = %d, want 2", playout.fileChannels)
	}
	if args := strings.Join(cmd.Args, " "); !strings.Contains(args, "-ac 2 ") {
		t.Errorf("decoder args = %s, want -ac 2", args)
	}
	names := recordingChannels(file)
	if len(names) != 2 || names[0].Name != "Ch 1" || names[1].Name != "Ch 2" {
		t.Errorf("default names = %+v, want two numbered channels", names)
	}
	row := buildRecordingRow(file)
	if row.Channels != 2 || len(row.ChanNames) != 2 {
		t.Errorf("row = %+v", row)
	}

	labels := []recChannel{{Number: 1, Name: "Left", Source: "Input@source", Device: "RX 1"}, {Number: 2, Name: "Right", Device: "RX 2"}}
	if err := writeRecordingChannels(file, labels, false); err != nil {
		t.Fatal(err)
	}
	if got := recordingChannels(file); len(got) != 2 || got[0] != labels[0] || got[1] != labels[1] {
		t.Errorf("sidecar labels changed: %+v", got)
	}

	// Missing/incomplete headers still use the filename; no format uses the device count.
	if err := os.Remove(channelsSidecar(file)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, filepath.Join(t.TempDir(), filepath.Base(file))} {
		mutex.Lock()
		got := takeChannels(path)
		mutex.Unlock()
		if got != 8 || len(recordingChannels(path)) != 8 {
			t.Errorf("filename fallback for %s: %d", path, got)
		}
	}
	mutex.Lock()
	unknown := takeChannels(filepath.Join(t.TempDir(), "unknown.wav"))
	mutex.Unlock()
	if unknown != 2 {
		t.Errorf("device fallback = %d, want 2", unknown)
	}
}

func TestValidatePlaybackMetadataWithoutRecognizedName(t *testing.T) {
	mutex.Lock()
	oldRate, oldChannels := sampleRateIdx, channelCount
	mutex.Unlock()
	t.Cleanup(func() {
		mutex.Lock()
		sampleRateIdx, channelCount = oldRate, oldChannels
		mutex.Unlock()
	})
	dir := t.TempDir()
	for _, name := range []string{"renamed.wav", "Show_20261399_120000_ch8_96kHz.wav"} {
		path := filepath.Join(dir, name)
		writeTestWAV(t, path, 0, true) // valid mono 48 kHz header, regardless of name
		if row := buildRecordingRow(path); row.Channels != 0 || row.SampleRate != 0 || row.Format != "" {
			t.Errorf("row naming policy changed: %+v", row)
		}
		for _, tc := range []struct {
			rate, channels int
			notice         string
		}{
			{1, 1, ""},
			{0, 1, "SAMPLE RATE MISMATCH"},
			{1, 2, "CHANNEL COUNT MISMATCH"},
			{0, 2, "RATE + CHANNEL MISMATCH"},
		} {
			mutex.Lock()
			sampleRateIdx, channelCount = tc.rate, tc.channels
			err := validatePlaybackFile(path)
			mutex.Unlock()
			if tc.notice == "" {
				if err != nil {
					t.Errorf("%s: matching header refused: %v", name, err)
				}
			} else if m, ok := err.(*playbackMismatch); !ok || m.panelNotice() != tc.notice {
				t.Errorf("%s at device rate index %d/%dch: got %v, want %s", name, tc.rate, tc.channels, err, tc.notice)
			}
		}
	}
	// Neither a readable format nor a filename format provides evidence to refuse.
	unknown := filepath.Join(dir, "unknown.wav")
	for _, data := range [][]byte{nil, []byte("RIFF")} {
		if err := os.WriteFile(unknown, data, 0600); err != nil {
			t.Fatal(err)
		}
		mutex.Lock()
		err := validatePlaybackFile(unknown)
		mutex.Unlock()
		if err != nil {
			t.Errorf("unknown format refused: %v", err)
		}
	}
}
