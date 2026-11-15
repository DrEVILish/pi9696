package main

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Exercise the handoff through the recording caller, including reader-exit
// refusal and the metadata fallback retained until the layout transaction fix.
func TestInputHandoffRecording(t *testing.T) {
	for _, tt := range []struct {
		name        string
		mode        int
		ack         bool
		monitorExit string
		channels    int
	}{
		{"off leaves FIFO undrained", tcRecordOff, false, "", 2},
		{"metadata acknowledges audio layout", tcRecordMeta, true, "", 2},
		{"audio acknowledges extra channel", tcRecordAudio, true, "", 3},
		{"audio timeout falls back to metadata", tcRecordAudio, false, "", 2},
		{"monitor timeout refuses take", tcRecordOff, false, "timeout", 2},
		{"missing monitor completion refuses take", tcRecordOff, false, "missing", 2},
		{"confirmed monitor exit permits take", tcRecordOff, false, "exited", 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			initTestHardware(t)
			ensureMonitorDown(t)
			fakeExecutable(t, "ffmpeg", "#!/bin/sh\nexit 0\n")
			setTimecodeSettings(t, tcSourceLTC, tt.mode, false)

			// A locked LTC stream makes the acknowledged first position
			// distinguishable from a wall-clock/time-of-day fallback.
			const sr, first = 48000, 12345
			start := Timecode{10, 0, 0, 0}
			stream := new(int)
			now := time.Now()
			for pos := 0; pos < sr/2; pos += 1024 {
				tcFeedLTC(stream, ltcStream(start, sr, 3, int64(pos), 1024), 3, int64(pos), now, sr)
			}

			mutex.Lock()
			oldMode, oldState, oldPath := demoMode, infernoState, fifoPath
			oldRate, oldChannels := sampleRateIdx, channelCount
			oldLastRate, oldLastChannels, oldLastLatency := lastSampleRate, lastChannelCount, lastRxLatencyNs
			oldRestarting, oldDeferred := infernoRestarting, infernoRestartDeferred
			oldCtl, oldLayoutWait, oldMonitorWait := rxFifoCtl, fifoLayoutWait, monitorHandoffWait
			oldMonitorCmd, oldMonitorDone, oldMonitoring := monitorCmd, monitorDone, monitoring
			oldAudio, oldStart, oldFile := tcAudioTake, recordStart, recordingFile
			oldTransport := currentState
			oldNotice, oldNoticeUntil := sysNotice, sysNoticeUntil
			demoMode, infernoState, fifoPath = false, InfernoRunning, "characterization-only.raw"
			sampleRateIdx, channelCount = 1, 2
			lastSampleRate, lastChannelCount, lastRxLatencyNs = sr, 2, rxLatencyNs
			infernoRestarting, infernoRestartDeferred = false, false
			rxFifoCtl = make(chan fifoLayoutReq)
			fifoLayoutWait, monitorHandoffWait = time.Millisecond, 0
			monitorCmd, monitorDone, monitoring = nil, nil, false
			currentState = StateIdle
			if tt.monitorExit != "" {
				// An unclosed completion is an outgoing reader whose exit
				// was not confirmed. No process signal is needed for this case.
				monitorCmd = &exec.Cmd{}
				monitorDone, monitoring = make(chan struct{}), true
				if tt.monitorExit == "missing" {
					monitorDone = nil
				} else if tt.monitorExit == "exited" {
					close(monitorDone)
					monitorHandoffWait = time.Second
				}
			}
			if tt.ack || tt.mode == tcRecordOff {
				// Buffer the captured request only for inspection; the
				// production control channel remains unbuffered.
				fifoLayoutWait = time.Second
			}
			requests := make(chan fifoLayoutReq, 1)
			stop := make(chan struct{})
			writerDone := make(chan struct{})
			ctl := rxFifoCtl
			if tt.ack || tt.mode == tcRecordOff {
				go func() {
					defer close(writerDone)
					select {
					case req := <-ctl:
						requests <- req
						req.reply <- first
					case <-stop:
					}
				}()
			} else {
				close(writerDone)
			}

			outgoing, outgoingDone, oldMeterGen := monitorCmd, monitorDone, meterGen
			refuse := tt.monitorExit == "timeout" || tt.monitorExit == "missing"
			startRecording()
			if refuse && !isRecording {
				// Repeated Record and direct monitor starts must retain the
				// same outgoing reader until its exit can be confirmed.
				for attempt := 0; attempt < 2; attempt++ {
					startRecording()
					startMonitor()
				}
			}
			if refuse {
				if isRecording || ffmpegCmd != nil {
					t.Error("take process opened before monitor exit was confirmed")
				}
				if !monitoring || monitorCmd != outgoing || monitorDone != outgoingDone {
					t.Error("unconfirmed outgoing reader ownership was lost")
				}
				if meterGen != oldMeterGen {
					t.Error("unconfirmed reader exit allocated new meters")
				}
				if sysNotice != "RECORD FAILED - SEE LOG" {
					t.Errorf("missing short refusal notice: %q", sysNotice)
				}
			}
			cmd, done, file := ffmpegCmd, recordingDone, recordingFile
			rec, audio, mon := isRecording, tcAudioTake, monitoring
			if tt.monitorExit == "exited" && (monitorCmd != nil || mon) {
				t.Error("confirmed outgoing reader was not disowned before take meters")
			}
			var args []string
			if cmd != nil {
				args = append(args, cmd.Args...)
			}
			// Let the real recording reaper finish without restoring an
			// input monitor or requesting another layout from the fake source.
			tcAudioTake, infernoState, currentState = false, InfernoStopped, StateSettings
			monitorCmd, monitorDone, monitoring = nil, nil, false
			mutex.Unlock()
			close(stop)
			<-writerDone

			t.Cleanup(func() {
				if rec {
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Fatal("recording child was not reaped")
					}
				}
				mutex.Lock()
				demoMode, infernoState, fifoPath = oldMode, oldState, oldPath
				sampleRateIdx, channelCount = oldRate, oldChannels
				lastSampleRate, lastChannelCount, lastRxLatencyNs = oldLastRate, oldLastChannels, oldLastLatency
				infernoRestarting, infernoRestartDeferred = oldRestarting, oldDeferred
				rxFifoCtl, fifoLayoutWait, monitorHandoffWait = oldCtl, oldLayoutWait, oldMonitorWait
				monitorCmd, monitorDone, monitoring = oldMonitorCmd, oldMonitorDone, oldMonitoring
				tcAudioTake, recordStart, recordingFile = oldAudio, oldStart, oldFile
				currentState = oldTransport
				sysNotice, sysNoticeUntil = oldNotice, oldNoticeUntil
				mutex.Unlock()
			})
			if refuse {
				return
			}
			if !rec {
				t.Fatal("handoff did not start recording")
			}
			if mon || audio != (tt.mode == tcRecordAudio && tt.ack) {
				t.Fatalf("monitoring=%v, audio=%v", mon, audio)
			}
			if !strings.Contains(strings.Join(args, " "), "-ac "+strconv.Itoa(tt.channels)+" -i") {
				t.Fatalf("wrong input channels: %v", args)
			}
			sc, err := readRecordingSidecar(file)
			if err != nil {
				t.Fatal(err)
			}
			if tt.mode == tcRecordOff {
				if sc.Timecode != nil {
					t.Fatal("TC Off unexpectedly stamped the take")
				}
				select {
				case <-requests:
					t.Fatal("TC Off unexpectedly requested a FIFO drain/layout")
				default:
				}
			} else if sc.Timecode == nil {
				t.Fatal("missing metadata stamp")
			}
			if tt.ack {
				req := <-requests
				if req.withTC != (tt.mode == tcRecordAudio) {
					t.Fatalf("requested withTC=%v", req.withTC)
				}
				want := samplesFromFrames(start.frames(tcRates[tcRateDefault]), tcRates[tcRateDefault], sr) + first
				if sc.Timecode.TimeReference != want {
					t.Fatalf("stamp position=%d, want %d", sc.Timecode.TimeReference, want)
				}
			}
		})
	}
}

func TestInputHandoffConfirmedExitKeepsTakeMeters(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("real ffmpeg required for monitor/take meters")
	}
	initTestHardware(t)
	demoTestCleanup(t)
	resetTransportCleanup(t)
	setTimecodeSettings(t, tcSourceOff, tcRecordOff, false)
	ensureMonitorDown(t)
	t.Cleanup(func() { quiesceTransport(t) })
	mutex.Lock()
	setDemoModeLocked(true)
	startMonitor()
	outgoing, oldCmd, oldGen := monitorDone, monitorCmd, meterGen
	mutex.Unlock()
	if outgoing == nil || oldCmd == nil {
		t.Fatal("input monitor did not start")
	}
	waitFor(t, 3*time.Second, "live monitor meters", func() bool {
		mutex.Lock()
		defer mutex.Unlock()
		return meterPeakDB > meterSilence
	})

	mutex.Lock()
	startRecording()
	rec, disowned, gen := isRecording, monitorCmd == nil && !monitoring, meterGen
	exited := false
	select {
	case <-outgoing:
		exited = true
	default:
	}
	mutex.Unlock()
	if !rec || !exited || !disowned || gen <= oldGen {
		t.Fatalf("take=%v, reader exited=%v, disowned=%v, meter generation=%d (old %d)",
			rec, exited, disowned, gen, oldGen)
	}
	// The old process reaper can now acquire the app mutex. Fresh take meters
	// must remain allocated and receive live samples after that handoff.
	waitFor(t, 3*time.Second, "live take meters after monitor exit", func() bool {
		mutex.Lock()
		defer mutex.Unlock()
		return isRecording && meterGen == gen && len(meterChannelPeak) == channelCount &&
			len(meterChannelRMS) == channelCount && meterPeakDB > meterSilence
	})
}
