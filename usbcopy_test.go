package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyCannotEscapeUSB(t *testing.T) {
	for _, kind := range []string{"temporary link", "directory link"} {
		t.Run(kind, func(t *testing.T) {
			usb, outside := t.TempDir(), t.TempDir()
			src := filepath.Join(t.TempDir(), "take.wav")
			victim := filepath.Join(outside, "take.wav.tmp")
			os.WriteFile(src, []byte("audio"), 0644)
			os.WriteFile(victim, []byte("keep"), 0644)
			dst := filepath.Join(usb, "take.wav")
			if kind == "temporary link" {
				os.Symlink(victim, dst+".tmp")
			} else {
				os.Symlink(outside, filepath.Join(usb, "day"))
				dst = filepath.Join(usb, "day", "take.wav")
			}
			root, err := os.OpenRoot(usb)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			rel, _ := filepath.Rel(usb, dst)
			copyFile(src, root, rel, func() bool { return false })
			b, _ := os.ReadFile(victim)
			if string(b) != "keep" {
				t.Fatalf("outside file overwritten: %q", b)
			}
			if _, err := os.Stat(filepath.Join(outside, "take.wav")); err == nil {
				t.Fatal("copy escaped through directory link")
			}
		})
	}
}
