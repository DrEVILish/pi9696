package main

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Exercise the handoff through the recording caller, including reader-exit
// refusal and confirmed layouts/positions.
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
		{"audio timeout refuses take", tcRecordAudio, false, "", 2},
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
			oldTransport, oldRecovery := currentState, inputRecovery
			oldNotice, oldNoticeUntil := sysNotice, sysNoticeUntil
			demoMode, infernoState, fifoPath = false, InfernoRunning, "characterization-only.raw"
			sampleRateIdx, channelCount = 1, 2
			lastSampleRate, lastChannelCount, lastRxLatencyNs = sr, 2, rxLatencyNs
			infernoRestarting, infernoRestartDeferred = false, false
			rxFifoCtl = make(chan fifoLayoutReq)
			fifoLayoutWait, monitorHandoffWait = time.Millisecond, 0
			monitorCmd, monitorDone, monitoring = nil, nil, false
			currentState = StateIdle
			inputRecovery = inputRecoveryState{}
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
						close(req.done)
					case <-stop:
					}
				}()
			} else {
				close(writerDone)
			}

			outgoing, outgoingDone, oldMeterGen := monitorCmd, monitorDone, meterGen
			readerRefusal := tt.monitorExit == "timeout" || tt.monitorExit == "missing"
			refuse := readerRefusal || (tt.mode == tcRecordAudio && !tt.ack)
			startRecording()
			if readerRefusal && !isRecording {
				// Repeated Record and direct monitor starts must retain the
				// same outgoing reader until its exit can be confirmed.
				for attempt := 0; attempt < 2; attempt++ {
					startRecording()
					startMonitor()
				}
			}
			if refuse {
				if !readerRefusal && !monitoring {
					t.Error("safe failed layout left audio metering stopped")
				}
				if isRecording || ffmpegCmd != nil {
					t.Error("take process opened without confirmed input handoff")
				}
				if readerRefusal && (!monitoring || monitorCmd != outgoing || monitorDone != outgoingDone) {
					t.Error("unconfirmed outgoing reader ownership was lost")
				}
				if readerRefusal && meterGen != oldMeterGen {
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
			inputRecovery = inputRecoveryState{}
			recoveryDone, recoveryMon := monitorDone, monitoring && !readerRefusal
			monitorCmd, monitorDone, monitoring = nil, nil, false
			mutex.Unlock()
			if recoveryMon {
				<-recoveryDone
			}
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
				currentState, inputRecovery = oldTransport, oldRecovery
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

func TestInputHandoffFailedRestoreBlocksReaders(t *testing.T) {
	for _, successor := range []bool{false, true} {
		t.Run(strconv.FormatBool(successor), func(t *testing.T) {
			initTestHardware(t)
			ensureMonitorDown(t)
			fakeExecutable(t, "ffmpeg", "#!/bin/sh\nexit 0\n")
			setTimecodeSettings(t, tcSourceOff, tcRecordAudio, false)
			fd := handoffTestFIFO(t)
			mutex.Lock()
			oldMode, oldState, oldPath, oldQuit := demoMode, infernoState, fifoPath, inProcRxQuit
			oldCtl, oldWait := rxFifoCtl, fifoLayoutWait
			oldAudio, oldTransport, oldRecovery := tcAudioTake, currentState, inputRecovery
			demoMode, infernoState, fifoPath, inProcRxQuit = false, InfernoRunning, "restoration-test.raw", make(chan struct{})
			rxFifoCtl, fifoLayoutWait = make(chan fifoLayoutReq), 100*time.Millisecond
			ctl := rxFifoCtl
			f := fifoFeed{fd: fd, ctl: make(chan fifoLayoutReq, 1)}
			served := make(chan struct{})
			go func() {
				f.ctl <- <-ctl
				f.serve()
				close(served)
			}()
			input, err := prepareTakeInputLocked()
			<-served
			if err != nil || input.channels != channelCount+1 || !f.withTC {
				t.Errorf("could not establish TC layout: %+v, %v", input, err)
			}
			// No writer accepts restoration; this source stays TC even though
			// the take's recording semantics have ended.
			tcEndAudioTakeLocked()
			if tcAudioTake {
				t.Error("take semantics remained active after the take ended")
			}
			tcRecordIdx = tcRecordOff
			_, nextErr := prepareTakeInputLocked()
			startMonitor()
			if nextErr == nil {
				t.Error("next take permitted an unrestored TC layout")
			}
			if monitoring {
				t.Error("monitor opened an unrestored TC layout")
			}
			if successor {
				// Keep exactly the same path. Only the writer lifetime changes,
				// so an old source's restoration must not affect its successor.
				inProcRxQuit = make(chan struct{})
				startMonitor()
			} else {
				served = make(chan struct{})
				go func() {
					f.ctl <- <-ctl
					f.serve()
					close(served)
				}()
				startMonitor()
				<-served
				if f.withTC {
					t.Error("successful retry did not restore audio layout")
				}
			}
			if !monitoring || inputRecovery.restoreAudio {
				t.Error("audio monitor did not recover")
			}
			done, mon := monitorDone, monitoring
			monitorCmd, monitoring = nil, false
			infernoState, currentState = InfernoStopped, StateSettings
			mutex.Unlock()
			if mon {
				<-done
			}
			mutex.Lock()
			demoMode, infernoState, fifoPath, inProcRxQuit = oldMode, oldState, oldPath, oldQuit
			rxFifoCtl, fifoLayoutWait = oldCtl, oldWait
			tcAudioTake, currentState, inputRecovery = oldAudio, oldTransport, oldRecovery
			mutex.Unlock()
		})
	}
}

func TestInputHandoffCanceledDrainRecoversMonitor(t *testing.T) {
	for _, mode := range []int{tcRecordMeta, tcRecordAudio} {
		t.Run(strconv.Itoa(mode), func(t *testing.T) {

			initTestHardware(t)
			ensureMonitorDown(t)
			fakeExecutable(t, "ffmpeg", "#!/bin/sh\nexit 0\n")
			setTimecodeSettings(t, tcSourceOff, mode, false)
			fd := handoffTestFIFO(t)
			mutex.Lock()
			oldMode, oldState, oldQuit := demoMode, infernoState, inProcRxQuit
			oldCtl, oldWait, oldRecovery := rxFifoCtl, fifoLayoutWait, inputRecovery
			oldTransport := currentState
			demoMode, infernoState, inProcRxQuit = false, InfernoRunning, make(chan struct{})
			rxFifoCtl, fifoLayoutWait = make(chan fifoLayoutReq), 100*time.Millisecond
			ctl := rxFifoCtl
			f := fifoFeed{fd: fd, ctl: make(chan fifoLayoutReq, 1), async: &fifoAsync{
				queue: make(chan fifoChunk, 1), free: make(chan []byte, 1),
			}}
			f.async.mu.Lock()
			accepted, served := make(chan struct{}), make(chan struct{})
			go func() {
				f.ctl <- <-ctl
				close(accepted)
				f.serve()
				close(served)
			}()
			// The actual handoff retires its old reader before the held request.
			oldCmd, oldDone, oldMonitoring := monitorCmd, monitorDone, monitoring
			monitorCmd, monitorDone, monitoring = &exec.Cmd{}, make(chan struct{}), true
			close(monitorDone)
			_, err := prepareTakeInputLocked()
			<-accepted
			if err == nil {
				t.Error("take preparation succeeded before the canceled drain completed")
			}
			tcRecordIdx = tcRecordOff
			if _, err := prepareTakeInputLocked(); err == nil {
				t.Error("TC-Off take preparation succeeded before the canceled drain completed")
			}
			startMonitor() // pending drain must keep a replacement reader out
			if monitoring {
				t.Error("monitor opened while the canceled drain was still pending")
			}
			f.async.mu.Unlock()
			<-served
			startMonitor() // cancellation completed; audio never changed, no restore needed
			if !monitoring || f.withTC || inputRecovery.restoreAudio {
				t.Error("safe canceled request did not recover the audio monitor")
			}
			done, mon := monitorDone, monitoring
			monitorCmd, monitoring = nil, false
			infernoState, currentState = InfernoStopped, StateSettings
			mutex.Unlock()
			if mon {
				<-done
			}
			mutex.Lock()
			demoMode, infernoState, inProcRxQuit = oldMode, oldState, oldQuit
			rxFifoCtl, fifoLayoutWait, inputRecovery = oldCtl, oldWait, oldRecovery
			monitorCmd, monitorDone, monitoring = oldCmd, oldDone, oldMonitoring
			currentState = oldTransport
			mutex.Unlock()

		})
	}
}

func TestInputHandoffFailedAudioStartRestoresMonitor(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("real ffmpeg required")
	}
	initTestHardware(t)
	demoTestCleanup(t)
	resetTransportCleanup(t)
	setTimecodeSettings(t, tcSourceLTC, tcRecordAudio, false)
	ensureMonitorDown(t)
	t.Cleanup(func() { quiesceTransport(t) })
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	mutex.Lock()
	setDemoModeLocked(true)
	currentState = StateIdle
	startMonitor()
	oldPath := RecordPath
	RecordPath = filepath.Join(blocker, "takes")
	startRecording() // layout succeeds, but the output path cannot be created
	RecordPath = oldPath
	rec, mon, audio, restore := isRecording, monitoring, tcAudioTake, inputRecovery.restoreAudio
	mutex.Unlock()
	if rec || !mon || audio || restore {
		t.Fatalf("failed audio take recovery: recording=%v monitor=%v audio=%v restore=%v", rec, mon, audio, restore)
	}
}

func TestInputHandoffDemoStampMatchesFirstAudioSample(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("real ffmpeg required")
	}
	initTestHardware(t)
	demoTestCleanup(t)
	resetTransportCleanup(t)
	setTimecodeSettings(t, tcSourceLTC, tcRecordAudio, false)
	ensureMonitorDown(t)
	t.Cleanup(func() { quiesceTransport(t) })
	mutex.Lock()
	sampleRateIdx, channelCount = 1, 2
	setDemoModeLocked(true)
	currentState = StateIdle
	startMonitor()
	mutex.Unlock()
	waitFor(t, 3*time.Second, "demo LTC lock", func() bool { return tcInputNow(time.Now()).locked })
	mutex.Lock()
	startRecording()
	rec, file := isRecording, recordingFile
	mutex.Unlock()
	if !rec {
		t.Fatal("demo audio take did not start")
	}
	waitFor(t, 3*time.Second, "demo take samples", func() bool {
		mutex.Lock()
		defer mutex.Unlock()
		return meterPeakDB > meterSilence
	})
	quiesceTransport(t)
	sc, err := readRecordingSidecar(file)
	if err != nil || sc.Timecode == nil || sc.Timecode.Source != "LTC" {
		t.Fatalf("demo stamp: %+v, %v", sc, err)
	}
	ref, err := wavTimeReference(file)
	if err != nil || ref != sc.Timecode.TimeReference {
		t.Fatalf("WAV reference %d (%v), sidecar %+v", ref, err, sc.Timecode)
	}
	raw, err := exec.Command("ffmpeg", "-v", "error", "-i", file, "-f", "s32le", "-").Output()
	if err != nil {
		t.Fatal(err)
	}
	samples := make([]int32, len(raw)/4)
	for i := range samples {
		samples[i] = int32(binary.LittleEndian.Uint32(raw[4*i:]))
	}
	code := decodeLTCChannel(samples, 3, 2, 48000)
	if len(code) == 0 {
		t.Fatal("no LTC decoded from demo take")
	}
	rate := tcRates[tcRateDefault]
	first := code[0]
	recorded := samplesFromFrames(first.tc.frames(rate)+1, rate, 48000) - first.endPos
	if delta := recorded - ref; delta < -2 || delta > 2 {
		t.Fatalf("demo first audio sample reference %d, metadata %d", recorded, ref)
	}
}
