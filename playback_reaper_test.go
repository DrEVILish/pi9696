package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"pi9696/hardware"
	"strings"
	"sync"
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

// The real start/seek entry paths must connect decoder output to the pump,
// retaining the requested offsets and letting its final output reach EOF.
func TestPlaybackStartAndSeekLaunchTx(t *testing.T) {
	initTestHardware(t)
	saveTxGlobals(t)
	resetTransportCleanup(t)
	setTimecodeSettings(t, tcSourceOff, tcRecordMeta, false)
	fakeExecutable(t, "ffmpeg", "#!/bin/sh\nprintf '\\001\\000\\000\\000\\002\\000\\000\\000'\nkill -STOP $$\nexit 0\n")
	file := filepath.Join(t.TempDir(), "recording_20260101_000000_ch2_48kHz.wav")
	if err := os.WriteFile(file, []byte("fake"), 0644); err != nil {
		t.Fatal(err)
	}
	holder := &fakeTxHolder{}
	mutex.Lock()
	origInferno := infernoState
	infernoState, demoMode = InfernoStopped, false
	currentState, isRecording = StateIdle, false
	sampleRateIdx, channelCount = 1, 2
	txHolder, txHolderReady, txHolderChannels = holder, true, 3
	mutex.Unlock()
	t.Cleanup(func() {
		mutex.Lock()
		cmd, done := playbackCmd, playbackDone
		mutex.Unlock()
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
			waitReaped(t, done, "TX playback cleanup")
		}
		waitFor(t, 3*time.Second, "TX pumps to retire", func() bool { return txPumpsActive.Load() == 0 })
		mutex.Lock()
		infernoState = origInferno
		mutex.Unlock()
	})

	mutex.Lock()
	started := startPlaybackFrom(file, 2*time.Second)
	cmd, done := playbackCmd, playbackDone
	mutex.Unlock()
	if !started {
		t.Fatal("TX playback did not start")
	}

	for i, pos := range []time.Duration{2 * time.Second, 5 * time.Second} {
		if i > 0 {
			mutex.Lock()
			restartPlaybackAt(pos)
			cmd, done = playbackCmd, playbackDone
			mutex.Unlock()
			if cmd == nil {
				t.Fatal("TX seek did not start")
			}
		}
		waitProcessStopped(t, cmd.Process.Pid)
		waitFor(t, 3*time.Second, "decoded audio at TX", func() bool {
			count := 0
			for _, sample := range holder.flattened() {
				if sample != 0 {
					count++
				}
			}
			return count >= (i+1)*2
		})
		mutex.Lock()
		state, via, loaded, elapsed := currentState, playbackViaDante, playbackFile, playbackPosition()
		mutex.Unlock()
		if state != StatePlaying || !via || loaded != file || elapsed < pos || elapsed > pos+time.Second {
			t.Fatalf("playback publication: state=%v via=%v file=%q position=%v", state, via, loaded, elapsed)
		}
		want := "-ss " + []string{"2.000", "5.000"}[i]
		if !strings.Contains(strings.Join(cmd.Args, " "), want) {
			t.Fatalf("decoder args %v omit %q", cmd.Args, want)
		}
	}
	if err := cmd.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	waitReaped(t, done, "TX natural EOF")
	waitFor(t, 3*time.Second, "TX EOF drain", func() bool { return txPumpsActive.Load() == 0 })
	var audio []int32
	for _, sample := range holder.flattened() {
		if sample != 0 {
			audio = append(audio, sample)
		}
	}
	if !equalInt32(audio, []int32{1, 2, 1, 2}) {
		t.Fatalf("TX audio %v, want both decoded frames", audio)
	}
}

type gatedPlaybackHolder struct {
	fakeTxHolder
	first, quiet     sync.Once
	entered, release chan struct{}
	silence, resume  chan struct{}
}

func (h *gatedPlaybackHolder) Write(b []int32) (int, error) {
	h.first.Do(func() { close(h.entered); <-h.release })
	if h.silence != nil {
		zero := true
		for _, v := range b {
			if v != 0 {
				zero = false
				break
			}
		}
		if zero {
			h.quiet.Do(func() { close(h.silence); <-h.resume })
		}
	}
	return h.fakeTxHolder.Write(b)
}

func TestPlaybackOwnsOutputAfterDecoderExit(t *testing.T) {
	for _, action := range []string{"natural", "stop", "pause", "chase-loss"} {
		t.Run(action, func(t *testing.T) {
			initTestHardware(t)
			saveTxGlobals(t)
			resetTransportCleanup(t)
			setTimecodeSettings(t, tcSourceOff, tcRecordOff, false)
			fakeExecutable(t, "ffmpeg", "#!/bin/sh\nhead -c 16384 /dev/zero | tr '\\000' '\\001'\n")
			file := filepath.Join(t.TempDir(), "Show_20260101_120000_ch2_48kHz.wav")
			if err := os.WriteFile(file, nil, 0600); err != nil {
				t.Fatal(err)
			}
			h := &gatedPlaybackHolder{entered: make(chan struct{}), release: make(chan struct{})}
			if action == "pause" {
				h.silence, h.resume = make(chan struct{}), make(chan struct{})
			}
			var release, resume sync.Once
			mutex.Lock()
			oldInferno, oldChase := infernoState, tcChase
			infernoState, demoMode = InfernoStopped, false
			currentState, isRecording = StateIdle, false
			sampleRateIdx, channelCount = 1, 2
			txHolder, txHolderReady, txHolderChannels = h, true, 3
			started := startPlaybackFrom(file, 0)
			cmd, done := playbackCmd, playbackDone
			mutex.Unlock()
			t.Cleanup(func() {
				release.Do(func() { close(h.release) })
				if h.resume != nil {
					resume.Do(func() { close(h.resume) })
				}
				if cmd != nil && cmd.Process != nil {
					_ = cmd.Process.Kill()
				}
				waitReaped(t, done, "playback output cleanup")
				waitFor(t, 3*time.Second, "output pump retirement", func() bool { return txPumpsActive.Load() == 0 })
				mutex.Lock()
				infernoState, tcChase = oldInferno, oldChase
				tcSetChaseLive(nil)
				mutex.Unlock()
			})
			if !started {
				t.Fatal("playback did not start")
			}
			select {
			case <-h.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("pump did not write")
			}
			// The OS process is reaped while its first output write remains gated.
			waitFor(t, 3*time.Second, "decoder reaped", func() bool { _, err := os.Stat(fmt.Sprintf("/proc/%d", cmd.Process.Pid)); return os.IsNotExist(err) })
			mutex.Lock()
			if currentState != StatePlaying || playbackCmd != cmd || !infernoBusyLocked() || !monitoringOutput {
				t.Error("decoder exit released live output ownership")
			}
			mutex.Unlock()
			select {
			case <-done:
				t.Error("playback completed before output retired")
			default:
			}
			switch action {
			case "stop":
				onButtonPress(hardware.StopButton)
			case "pause":
				onButtonPress(hardware.PlayButton)
			case "chase-loss":
				mutex.Lock()
				tcChase.cmd = cmd
				tcSetChaseLive(cmd)
				tcChaseStepLocked(tcReading{}, time.Now())
				mutex.Unlock()
			}
			release.Do(func() { close(h.release) })
			if action == "pause" {
				select {
				case <-h.silence:
				case <-done:
					t.Error("paused decoder EOF ended playback")
				case <-time.After(3 * time.Second):
					t.Fatal("paused output did not write silence")
				}
				mutex.Lock()
				paused := currentState == StatePaused
				mutex.Unlock()
				if !paused {
					t.Error("pause lost after decoder EOF")
				}
				onButtonPress(hardware.PlayButton)
				resume.Do(func() { close(h.resume) })
			}
			waitReaped(t, done, "complete playback")
			waitFor(t, 3*time.Second, "audio drain", func() bool { return txPumpsActive.Load() == 0 })
			nonzero := 0
			for _, v := range h.flattened() {
				if v != 0 {
					nonzero++
				}
			}
			want := 4096
			if action == "stop" || action == "chase-loss" {
				want = 2048
			}
			if nonzero != want {
				t.Errorf("%s delivered %d nonzero samples, want %d", action, nonzero, want)
			}
		})
	}
}
