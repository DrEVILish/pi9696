package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWifiSaveRestartsActiveAP(t *testing.T) {
	t.Setenv("PI9696_SIM", "")
	dir := t.TempDir()
	old := wifiConfigPath
	wifiConfigPath = filepath.Join(dir, "hostapd.conf")
	defer func() { wifiConfigPath = old }()
	running := filepath.Join(dir, "running")
	t.Setenv("WIFI_TEST_CONFIG", wifiConfigPath)
	t.Setenv("WIFI_TEST_RUNNING", running)
	// Model systemd's start semantics: an active service is not restarted by enable --now.
	fakeExecutable(t, "systemctl", `#!/bin/sh
case "$1" in
 enable) if [ "$2" = --now ] && [ ! -f "$WIFI_TEST_RUNNING" ]; then cp "$WIFI_TEST_CONFIG" "$WIFI_TEST_RUNNING"; fi;;
 restart) cp "$WIFI_TEST_CONFIG" "$WIFI_TEST_RUNNING";;
 disable) rm -f "$WIFI_TEST_RUNNING";;
esac
`)
	applyWifiConfig("OldAP", "oldpassword", true)
	applyWifiConfig("NewAP", "newpassword", true)
	data, err := os.ReadFile(running)
	if err != nil || !strings.Contains(string(data), "ssid=NewAP\n") || !strings.Contains(string(data), "wpa_passphrase=newpassword\n") {
		t.Fatalf("running AP did not adopt saved credentials: %v %s", err, data)
	}
	applyWifiConfig("NewAP", "newpassword", false)
	if _, err := os.Stat(running); !os.IsNotExist(err) {
		t.Fatal("disabled AP still running")
	}
}

func TestWifiApplyFailureIsVisible(t *testing.T) {
	t.Setenv("PI9696_SIM", "")
	old := wifiConfigPath
	wifiConfigPath = filepath.Join(t.TempDir(), "hostapd.conf")
	defer func() { wifiConfigPath = old }()
	mutex.Lock()
	oldNotice, oldWeb, oldUntil, oldWebUntil := sysNotice, webNotice, sysNoticeUntil, webNoticeUntil
	mutex.Unlock()
	defer func() {
		mutex.Lock()
		sysNotice, webNotice, sysNoticeUntil, webNoticeUntil = oldNotice, oldWeb, oldUntil, oldWebUntil
		mutex.Unlock()
	}()
	fakeExecutable(t, "systemctl", "#!/bin/sh\nexit 1\n")
	applyWifiConfig("AP", "password1", true)
	mutex.Lock()
	defer mutex.Unlock()
	if sysNotice != "WIFI APPLY FAILED" || !strings.Contains(webNotice, "failed") {
		t.Fatalf("failure invisible: %q / %q", sysNotice, webNotice)
	}
}
