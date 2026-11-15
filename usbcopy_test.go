package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestCopyRefusesUnmountedUSB(t *testing.T) {
	oldMP, oldMounts := USBMountPoint, procMountsPath
	oldMounted, oldSel, oldState := usbMounted, filesToCopy, currentState
	defer func() {
		USBMountPoint, procMountsPath = oldMP, oldMounts
		usbMounted, filesToCopy, currentState = oldMounted, oldSel, oldState
	}()
	USBMountPoint = t.TempDir()
	procMountsPath = filepath.Join(t.TempDir(), "mounts")
	os.WriteFile(procMountsPath, nil, 0600)
	f := "unmounted-copy.wav"
	src := filepath.Join(RecordPath, f)
	os.WriteFile(src, []byte("audio"), 0644)
	defer os.Remove(src)
	mutex.Lock()
	usbMounted = true
	filesToCopy = map[string]bool{f: true}
	startCopyOperation()
	done := copyDone
	started := isCopying
	mutex.Unlock()
	if started {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("copy stuck")
		}
	}
	if _, err := os.Stat(filepath.Join(USBMountPoint, f)); err == nil {
		t.Fatal("copy wrote into the bare mountpoint")
	}
	if started {
		t.Fatal("copy started without a USB mount")
	}
}

func TestCopyPinsDestinationAcrossRemoval(t *testing.T) {
	usb := filepath.Join(t.TempDir(), "usb")
	os.Mkdir(usb, 0755)
	root, err := os.OpenRoot(usb)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	src := filepath.Join(t.TempDir(), "take.wav")
	os.WriteFile(src, make([]byte, 2<<20), 0644)
	removed := false
	err = copyFile(src, root, "take.wav", func() bool {
		if !removed {
			os.Rename(usb, usb+"-removed")
			os.Mkdir(usb, 0755)
			removed = true
		}
		return false
	})
	if err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(usb); len(entries) != 0 {
		t.Fatal("copy followed replacement mountpoint onto system disk")
	}
	if st, err := os.Stat(filepath.Join(usb+"-removed", "take.wav")); err != nil || st.Size() != 2<<20 {
		t.Fatalf("copy lost pinned destination: %v %v", st, err)
	}
}
