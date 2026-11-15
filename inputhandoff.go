package main

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// takeInput is the handoff's channel layout and first capture position.
// positionKnown is false when no layout acknowledgement was received; TC Off
// leaves the FIFO undrained and does not request a position.
type takeInput struct {
	started       time.Time
	channels      int
	firstFrame    int64
	positionKnown bool
}

// monitorHandoffWait bounds how long startRecording (holding the app mutex)
// waits for the outgoing monitor ffmpeg to exit. At 128ch/48kHz the 4 MB FIFO
// holds ~170 ms, so the wait must stay short.
var monitorHandoffWait = 500 * time.Millisecond

// prepareTakeInputLocked retires the meter reader, then asks the active FIFO
// writer for the take's layout and first position. Caller holds the app mutex;
// FIFO writers must serve requests without acquiring it.
//
// Reader ownership is retained on failure, so neither another take nor a
// monitor can open the FIFO until the outgoing reader's exit is confirmed.
// An unacknowledged TC-audio layout still falls back to metadata.
func prepareTakeInputLocked() (takeInput, error) {
	// A named FIFO only supports one real reader at a time - concurrent
	// readers split frames between them. Wait for the outgoing monitor to
	// exit before the recorder opens the FIFO: what Inferno writes meanwhile
	// queues in the pipe, so the take starts contiguous. Measured before this
	// handoff: 2400 frames to the take, the next 2400 to the dying monitor.
	// SIGKILL, not stopMonitor's SIGTERM: a graceful ffmpeg exit takes ~300ms,
	// longer than the FIFO holds at 128ch, and the monitor only feeds meters.
	if monitoring {
		outgoing := monitorDone
		if monitorCmd != nil && monitorCmd.Process != nil {
			if err := monitorCmd.Process.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, os.ErrProcessDone) {
				logWarnf("monitor handoff: SIGKILL failed: %v", err)
			}
		}
		if outgoing == nil {
			return takeInput{}, errors.New("input monitor has no exit completion")
		}
		select {
		case <-outgoing:
		case <-time.After(monitorHandoffWait):
			return takeInput{}, errors.New("input monitor exit timed out")
		}
		// The process is gone. Disown it before allocating the take's meters
		// so its reaper, waiting for the app mutex, cannot clear them.
		monitorCmd = nil
		monitoring = false
	}

	input := takeInput{started: time.Now(), channels: channelCount}
	// The writer drains at the layout switch and replies with the stream
	// position used for the stamp. TC Off deliberately skips this drain.
	tcAudioTake = false
	if tcRecordIdx != tcRecordOff {
		input.firstFrame, input.positionKnown = fifoSetLayout(tcRecordIdx == tcRecordAudio)
		if tcRecordIdx == tcRecordAudio {
			if input.positionKnown {
				tcAudioTake = true
				input.channels++
			} else {
				logWarnf("Timecode: the audio input did not switch to the TIMECODE channel; recording timecode as metadata only")
			}
		}
	}
	return input, nil
}
