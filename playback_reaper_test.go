package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Exercise the reaper installed by each entry path, including their existing
// difference when a stale decoder exits after the transport has become idle.
func TestPlaybackReaperEntryPaths(t *testing.T) {
	for _, seek := range []bool{false, true} {
		name := "start"
		if seek {
			name = "seek"
		}
		for _, outcome := range []string{"current", "successor", "stale-idle"} {
			t.Run(name+"/"+outcome, func(t *testing.T) {
				initTestHardware(t)
				resetTransportCleanup(t)
				fakeExecutable(t, "ffmpeg", "#!/bin/sh\nkill -STOP $$\nexit 0\n")
				file := filepath.Join(t.TempDir(), "recording_20260101_000000_ch2_48kHz.wav")
				if err := os.WriteFile(file, []byte("fake"), 0644); err != nil {
					t.Fatal(err)
				}

				mutex.Lock()
				origDemo, origInferno := demoMode, infernoState
				demoMode, infernoState = false, InfernoStopped
				currentState, isRecording = StateIdle, false
				sampleRateIdx, channelCount = 1, 2
				started := startPlaybackFrom(file, 0)
				cmd, done := playbackCmd, playbackDone
				mutex.Unlock()
				t.Cleanup(func() {
					if cmd != nil && cmd.Process != nil {
						_ = cmd.Process.Kill()
						waitReaped(t, done, "playback cleanup")
					}
					mutex.Lock()
					mon, monDone := monitorCmd, monitorDone
					mutex.Unlock()
					if mon != nil && mon.Process != nil {
						_ = mon.Process.Kill()
						waitReaped(t, monDone, "monitor cleanup")
					}
					mutex.Lock()
					demoMode, infernoState = origDemo, origInferno
					mutex.Unlock()
				})
				if !started {
					t.Fatal("playback did not start")
				}
				waitProcessStopped(t, cmd.Process.Pid)
				if seek {
					mutex.Lock()
					restartPlaybackAt(5 * time.Second)
					cmd, done = playbackCmd, playbackDone
					mutex.Unlock()
					if cmd == nil {
						t.Fatal("seek did not start replacement")
					}
					waitProcessStopped(t, cmd.Process.Pid)
				}

				successor := exec.Command("true")
				successorDone := make(chan struct{})
				mutex.Lock()
				switch outcome {
				case "successor":
					playbackCmd, playbackDone = successor, successorDone
					currentState, playbackPausedElapsed = StatePaused, 7*time.Second
					monitoringOutput = true
				case "stale-idle":
					playbackCmd = nil
					currentState = StateIdle
					infernoState = InfernoRunning
				}
				mutex.Unlock()
				if err := cmd.Process.Signal(syscall.SIGCONT); err != nil {
					t.Fatal(err)
				}
				waitReaped(t, done, "playback EOF")

				mutex.Lock()
				defer mutex.Unlock()
				switch outcome {
				case "current":
					if playbackCmd != nil || currentState != StateIdle || monitoringOutput || playbackPausedElapsed != 0 {
						t.Fatal("current reaper did not clear playback")
					}
				case "successor":
					if playbackCmd != successor || playbackDone != successorDone || currentState != StatePaused ||
						playbackPausedElapsed != 7*time.Second || !monitoringOutput {
						t.Fatal("stale reaper changed successor transport")
					}
					select {
					case <-successorDone:
						t.Fatal("stale reaper closed successor completion")
					default:
					}
				case "stale-idle":
					if monitoring != !seek {
						t.Fatalf("stale idle reaper monitoring=%v, want %v", monitoring, !seek)
					}
				}
			})
		}
	}
}
