package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallerDefersClockChanges(t *testing.T) {
	raw, err := os.ReadFile("docs/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	source, ok := strings.CutSuffix(string(raw), "\nmain \"$@\"\n")
	if !ok {
		t.Fatal("installer entry point not found")
	}
	// Run the actual functions with filesystem paths confined to a temp tree
	// and every system-changing command stubbed. Never invoke installer main.
	source = strings.ReplaceAll(source, "/etc/", "$TEST_ROOT/etc/")
	stubs := `
mkdir() { :; }
install() { :; }
udevadm() { :; }
sed() { :; }
sleep() { :; }
say() { :; }
info() { :; }
systemctl() { printf '%s\n' "$*" >> "$CALL_LOG"; }
configure
REBOOT_NEEDED=$TEST_REBOOT
start
`
	for _, clock := range []string{"statime", "stub"} {
		for _, tc := range []struct {
			name, noStart, reboot string
			deferred              bool
		}{
			{"no_start", "1", "0", true},
			{"needs_reboot", "0", "1", true},
			{"normal", "0", "0", false},
		} {
			t.Run(clock+"/"+tc.name, func(t *testing.T) {
				root := t.TempDir()
				dir, log := filepath.Join(root, "install"), filepath.Join(root, "calls")
				for _, p := range []string{dir, filepath.Join(root, "etc/systemd/system")} {
					if err := os.MkdirAll(p, 0755); err != nil {
						t.Fatal(err)
					}
				}
				cmd := exec.Command("bash", "-c", source+stubs)
				cmd.Env = append(os.Environ(), "TEST_ROOT="+root, "CALL_LOG="+log, "PI9696_DIR="+dir, "PI9696_CLOCK="+clock, "PI9696_NO_START="+tc.noStart, "TEST_REBOOT="+tc.reboot)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("installer functions: %v: %s", err, out)
				}
				calls, err := os.ReadFile(log)
				if err != nil {
					t.Fatal(err)
				}
				text := string(calls)
				changesRuntime := strings.Contains(text, "--now") || strings.Contains(text, "stop ") || strings.Contains(text, "restart ")
				if tc.deferred && changesRuntime {
					t.Fatalf("deferred install changed running services:\n%s", text)
				}
				if !tc.deferred {
					unit, other := "statime", "pi9696-clock"
					if clock == "stub" {
						unit, other = other, unit
					}
					stop, clockStart, appStart := strings.Index(text, "stop "+other), strings.Index(text, "restart "+unit), strings.Index(text, "restart pi9696\n")
					if stop < 0 || clockStart < stop || appStart < clockStart {
						t.Fatalf("clock/app start order:\n%s", text)
					}
				}
			})
		}
	}
}
