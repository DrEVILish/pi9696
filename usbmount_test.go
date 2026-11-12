package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runUSBScript runs deploy/pi9696-usb.sh with mountpoint, lsblk, findmnt,
// mount and umount replaced by stubs that log their arguments. busy makes
// mountpoint report the mountpoint as taken, diskMounts is what lsblk lists
// for the parent disk, and source is findmnt's answer for the mountpoint.
func runUSBScript(t *testing.T, action, dev string, busy bool, diskMounts, source string) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "calls")
	stub := func(name, body string) {
		script := "#!/bin/sh\necho \"" + name + " $*\" >>" + log + "\n" + body + "\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	busyExit := "exit 1"
	if busy {
		busyExit = "exit 0"
	}
	stub("mountpoint", busyExit)
	stub("lsblk", `case "$*" in *PKNAME*) echo sda;; *) printf '%s' "`+diskMounts+`";; esac`)
	stub("findmnt", "echo "+source)
	stub("mount", "")
	stub("umount", "")
	cmd := exec.Command("sh", "deploy/pi9696-usb.sh", action, dev)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "PI9696_USB_MP="+filepath.Join(bin, "mp"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v: %s", action, dev, err, out)
	}
	calls, _ := os.ReadFile(log)
	return string(calls)
}

func TestUSBMountScript(t *testing.T) {
	mp := "/mp"
	if calls := runUSBScript(t, "start", "sda1", false, "\n\n", ""); !strings.Contains(calls, "mount /dev/sda1 ") || !strings.Contains(calls, mp) {
		t.Errorf("free drive was not mounted:\n%s", calls)
	}
	if calls := runUSBScript(t, "start", "sda1", true, "", ""); strings.Contains(calls, "\nmount ") {
		t.Errorf("a second drive was mounted over the first:\n%s", calls)
	}
	if calls := runUSBScript(t, "start", "sda3", false, "\n/boot/firmware\n/\n", ""); strings.Contains(calls, "\nmount ") {
		t.Errorf("a partition of the in-use root disk was mounted:\n%s", calls)
	}
	if calls := runUSBScript(t, "stop", "sda1", false, "", "/dev/sda1"); !strings.Contains(calls, "umount -l") {
		t.Errorf("pulled drive was not unmounted:\n%s", calls)
	}
	if calls := runUSBScript(t, "stop", "sdb1", false, "", "/dev/sda1"); strings.Contains(calls, "umount") {
		t.Errorf("pulling a skipped drive unmounted the mounted one:\n%s", calls)
	}
}
