package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func Test44100TakeUsesExactWAVRate(t *testing.T) {
	initTestHardware(t)
	file := filepath.Join(t.TempDir(), "recording_20261115_120000_ch2_44kHz.wav")
	cmd := exec.Command("ffmpeg", "-v", "error", "-f", "lavfi", "-i", "anullsrc=r=44100:cl=stereo", "-t", "1", "-c:a", "pcm_s24le", "-rf64", "always", file)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create WAV: %v %s", err, out)
	}
	mutex.Lock()
	sampleRateIdx = 0
	channelCount = 2
	err := validatePlaybackFile(file)
	mutex.Unlock()
	if err != nil {
		t.Fatalf("44.1kHz take refused at matching device rate: %v", err)
	}
	if got := playbackFileDuration(file); got != time.Second {
		t.Errorf("duration=%v, want 1s", got)
	}
	row := buildRecordingRow(file)
	if row.SampleRate != 44100 || row.RateKHz() != "44.1" {
		t.Errorf("row lost exact rate: %d (%s)", row.SampleRate, row.RateKHz())
	}
	renamed := filepath.Join(filepath.Dir(file), "recording_20261115_120000_ch2_48kHz.wav")
	if err := os.Rename(file, renamed); err != nil {
		t.Fatal(err)
	}
	if ch, hz := recordingFormat(renamed); ch != 2 || hz != 44100 {
		t.Errorf("WAV header did not override filename: %dch %dHz", ch, hz)
	}
	file = renamed
	if row.DurationStr != "00:00:01" {
		t.Errorf("row duration %q", row.DurationStr)
	}
	mutex.Lock()
	sampleRateIdx = 1
	err = validatePlaybackFile(file)
	mutex.Unlock()
	if err == nil {
		t.Fatal("44.1kHz take allowed at 48kHz")
	}
}
