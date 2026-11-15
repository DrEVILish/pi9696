package main

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordingZipCompanionFailures(t *testing.T) {
	for _, kind := range []string{"present", "legacy", "unreadable"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "Show_20260101_120000_ch1_48kHz.wav")
			writeTestWAV(t, file, 123, true)
			side := channelsSidecar(file)
			switch kind {
			case "present":
				if err := writeSidecar(file, recChannelsFile{Channels: []recChannel{{Number: 1, Name: "Voice"}}, Timecode: &recTimecode{TimeReference: 123, Rate: "25", SampleRate: 48000}}, false); err != nil {
					t.Fatal(err)
				}
			case "unreadable":
				if err := os.Mkdir(side, 0700); err != nil {
					t.Fatal(err)
				}
			}
			var buf bytes.Buffer
			if err := writeRecordingZip(&buf, dir, []string{file}); err != nil {
				t.Fatal(err)
			}
			z, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			if err != nil {
				t.Fatal(err)
			}
			entries := map[string][]byte{}
			for _, f := range z.File {
				r, err := f.Open()
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(r)
				r.Close()
				if err != nil {
					t.Fatal(err)
				}
				entries[f.Name] = data
			}
			manifest := string(entries["manifest.txt"])
			if !strings.Contains(manifest, "Files: 1\n") {
				t.Fatalf("audio count lost: %s", manifest)
			}
			incomplete := strings.Contains(manifest, "INCOMPLETE")
			if incomplete != (kind == "unreadable") {
				t.Fatalf("%s companion: incorrect completeness: %s", kind, manifest)
			}
			if kind == "unreadable" && !strings.Contains(manifest, filepath.Base(side)) {
				t.Fatalf("missing companion not named: %s", manifest)
			}
			got, present := entries[filepath.Base(side)]
			if present != (kind == "present") {
				t.Fatalf("%s companion entry present=%v", kind, present)
			}
			if kind == "present" {
				want, err := os.ReadFile(side)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatal("companion metadata changed in archive")
				}
			}
		})
	}
}
