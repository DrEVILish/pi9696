package main

// OLED front panel: the render loop, every screen and menu page, and the
// meter/peak-hold helpers they draw from. Split out of main.go unchanged;
// the state they read still lives there, under the app mutex.

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"pi9696/hardware"
)

func updateLoop() {
	nameThread(threadRender)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		render()
	}
}

// updateButtonLampsLocked drives the REC/PLAY button backlights (Round 3
// hardware; STOP has no lamp): REC lit while a take is running, PLAY lit
// while playback is active and flashing at ~2Hz while paused so a paused deck
// reads as "standing by" rather than finished. Called from the 100ms render
// tick; LampManager.Set only writes a pin when its state changes, so the
// steady-state lamps cost nothing. Must hold the app mutex.
func updateButtonLampsLocked() {
	if hwManager == nil || hwManager.Lamps == nil {
		return
	}
	lm := hwManager.Lamps
	lm.Set(hardware.RecLamp, isRecording)
	switch currentState {
	case StatePlaying:
		lm.Set(hardware.PlayLamp, true)
	case StatePaused:
		lm.Set(hardware.PlayLamp, time.Now().UnixMilli()/250%2 == 0)
	default:
		lm.Set(hardware.PlayLamp, false)
	}
}

func render() {
	mutex.Lock()
	defer mutex.Unlock()

	// Auto-dim/off the panel when nobody has touched it for a while; done
	// here (100ms render tick, under the app mutex) so the dim stage follows
	// wall-clock idle with no extra timers.
	applyAutoDimLocked(time.Now())

	// Drop an untouched menu back to the Standby status screen - same tick,
	// same lock, same idle clock as auto-dim above.
	applyMenuTimeoutLocked(time.Now())

	// Keep the demo generator matching the flag (self-heals a generator
	// that died unexpectedly); steady state is two bool checks.
	syncDemoGeneratorLocked()

	pushWaveformSample()

	updateButtonLampsLocked()

	// Mid-take low-space auto-stop (Round 3 design: a take must never be
	// allowed to run into no room and have ffmpeg die mid-write, corrupting
	// the WAV header). Checks at most once per second under the render tick,
	// which is far cheaper than the Statfs syscall and keeps the behaviour on
	// the same lock everything else uses.
	if isRecording {
		checkMidTakeDiskLocked()
	}

	hwManager.Clear()

	// QR screens (WiFi join code, idle network/token page) need the full
	// 64px height for 2px QR modules, so the status bar steps aside there.
	qrScreen := currentState == StateWifiQR ||
		(currentState == StateIdleBrowse && idleBrowsePage > idleVUPageCount())
	if !qrScreen {
		renderStatusBar()
	}

	switch currentState {
	case StateIdle:
		renderIdleScreen()
	case StateIdleBrowse:
		renderIdleBrowse()
	case StateRecording:
		renderRecordingScreen()
	case StatePlaying:
		renderPlayingScreen()
	case StatePaused:
		renderPlayingScreen()
	case StateSettings:
		renderSettingsMenu()
	case StateCopyFiles:
		renderCopyFilesMenu()
	case StateCopying:
		renderCopyProgress()
	case StateSystemOptions:
		renderSystemOptionsMenu()
	case StateNetworkInfo:
		renderNetworkInfo()
	case StateRemoteInfo:
		renderRemoteInfo()
	case StateWifi:
		renderWifiMenu()
	case StateWifiQR:
		renderWifiQRScreen()
	case StateAudio:
		renderAudioMenu()
	case StateTimecode:
		renderTimecodeMenu()
	case StateMetering:
		renderMeteringMenu()
	case StateDisplay:
		renderDisplayMenu()
	case StateConfirm:
		renderConfirmDialog()
	}

	// Skip the SPI push when the framebuffer is unchanged: Update() always
	// writes addr commands plus the full 8KB frame, and static screens
	// (idle, paused) re-render identical pixels at 10Hz. The hash compare
	// reuses the WebUI mirror's signal (see noteDisplayFrame); the
	// first-push flag covers a theoretical first-frame hash collision so
	// boot can never leave a dark panel.
	if !displayPushed || hwManager.FrameHash() != displayLastHash {
		// A dead SPI bus used to show a frozen-but-"fine" UI with nothing
		// in the logs. Report push failures, throttled: render ticks at
		// 10Hz and a hard bus fault would otherwise flood.
		if err := hwManager.Update(); err != nil {
			if now := time.Now(); now.Sub(lastDisplayErrLog) >= time.Minute {
				lastDisplayErrLog = now
				logErrorf("display push failed: %v", err)
			}
		}
		displayPushed = true
	}
	noteDisplayFrame()
}

// noteDisplayFrame bumps displaySeq when the panel framebuffer differs from
// the last render, so the WebUI mirror reloads on change instead of polling.
// Tracks the packed buffer (what the panel shows, and what gates the SPI
// push above) and the canvas (what the mirror PNG is encoded from) -
// canvas-only shifts would otherwise leave the mirror stale indefinitely.
// Must be called under the app mutex (render does).
func noteDisplayFrame() {
	h, c := hwManager.FrameHash(), hwManager.CanvasHash()
	if h != displayLastHash || c != displayLastCanvasHash {
		displayLastHash = h
		displayLastCanvasHash = c
		displaySeq++
	}
}

func renderStatusBar() {
	sampleRate := sampleRates[sampleRateIdx]
	// Use FiraCode ligatures: >= <= != === !== -> <- =>
	// WAV is uncompressed PCM at the output bit depth shown below.
	formatStr := fmt.Sprintf("%s WAV %dbit %dkHz %dch", time.Now().Format("15:04"), OutputBitsPerSample, sampleRate/1000, channelCount)

	// Right side - USB status with enhanced typography
	rightSide := ""
	if usbMounted && usbSize != "" {
		// Use arrow ligature -> for better visual connection
		rightSide = fmt.Sprintf("%s [USB]", usbSize)
	} else {
		rightSide = "[---]"
	}

	// Use context-aware FiraCode rendering with Inferno status
	infernoRunning := infernoUp()
	hwManager.DrawStatusBarWithInferno(formatStr, rightSide, infernoRunning)
}

func renderIdleScreen() {
	// Use context-aware rendering for standby state
	hwManager.DrawCenteredText("Standby", "idle", 32)

	// One-shot status flash for OLED actions that have no screen of their
	// own (config export/import), transient like the low-disk warning below.
	if time.Now().Before(sysNoticeUntil) {
		if time.Now().UnixMilli()/500%2 == 0 {
			hwManager.SwitchToContext("selected")
			hwManager.DrawCenteredText(sysNotice, "selected", 48)
		}
		return
	}

	// If a record was just refused for lack of space (see onButtonPress),
	// surface an explicit flashing warning instead of the usual remaining-time
	// readout so the operator knows why the button did nothing.
	if time.Now().Before(diskWarnUntil) {
		blinkOn := time.Now().UnixMilli()/500%2 == 0
		if blinkOn {
			hwManager.SwitchToContext("selected")
			hwManager.DrawCenteredText("LOW DISK <30m", "selected", 48)
			hwManager.DrawCenteredText("cannot record", "details", 58)
		}
		return
	}
	if time.Now().Before(clockWarnUntil) {
		if time.Now().UnixMilli()/500%2 == 0 {
			hwManager.SwitchToContext("selected")
			hwManager.DrawCenteredText("NO CLOCK SYNC", "selected", 48)
			hwManager.DrawCenteredText("cannot record", "details", 58)
		}
		return
	}

	// Someone just opened the WebUI login page (see handleLoginGet): show
	// the access token on the panel so the operator can read it off without
	// digging into Settings -> Remote Access. Must hold the app mutex.
	if loginTokenFreshLocked() {
		hwManager.DrawCenteredText("Web login token:", "details", 48)
		hwManager.DrawCenteredText("Token: "+formatToken(remoteToken), "selected", 58)
		return
	}

	// Time remaining with enhanced formatting using FiraCode features
	remaining := estimateRemainingTime()
	storage := getRemainingStorage()
	timeText := fmt.Sprintf("%s (%s) available", formatDuration(remaining), storage)
	hwManager.DrawCenteredText(timeText, "details", 48)

	hwManager.DrawCenteredText("Rotate for input levels", "details", 58)
}

// idleVUChannelsPerPage caps how many channels' worth of meters fit
// legibly across the 256px-wide panel at once (see renderIdleVUPage).
// Owner layout 2026-10-06: 16 per page (a bank pair, as on the WebUI).
const idleVUChannelsPerPage = 16

// idleVUPageCount is how many VU-meter pages idle-browse needs to cover
// every recording channel; onEncoderRotate's StateIdleBrowse case pages
// through these before wrapping into the network/token page.
func idleVUPageCount() int {
	pages := (channelCount + idleVUChannelsPerPage - 1) / idleVUChannelsPerPage
	if pages < 1 {
		pages = 1
	}
	return pages
}

// vuRangeOptions are the selectable VU-meter floor presets (Settings ->
// Meter Range); 0dBFS is always the top of the scale.
var vuRangeOptions = []float64{-48, -60, -72, -90, -120}

// peakHoldOptions are the selectable peak-hold durations (Settings -> Peak
// Hold) before decayPeakHold starts falling a channel's held peak back
// toward its instantaneous level; 0 means no hold at all. A ~3s default is
// the de-facto standard: ITU-R BS.1771 mandates at least 150ms, Pro Tools
// defaults to 3s, Logic offers 2/4/6s and broadcast practice is 3-5s.
var peakHoldOptions = []time.Duration{0, 500 * time.Millisecond, 1 * time.Second, 2 * time.Second, 3 * time.Second, 5 * time.Second}

func adjustVURange(direction int) {
	vuRangeIdx = ((vuRangeIdx+direction)%len(vuRangeOptions) + len(vuRangeOptions)) % len(vuRangeOptions)
	settingChanged()
}

func adjustPeakHold(direction int) {
	peakHoldIdx = ((peakHoldIdx+direction)%len(peakHoldOptions) + len(peakHoldOptions)) % len(peakHoldOptions)
	settingChanged()
}

func peakHoldLabel() string {
	d := peakHoldOptions[peakHoldIdx]
	if d == 0 {
		return "Off"
	}
	return d.String()
}

// idleVUCurve is the standard audio-meter log taper shared by the OLED and
// WebUI meters (see remote.go's client-side VU_CURVE): more of the scale's
// display height given to the top of the range than the bottom, rather
// than a plain linear mapping. Expressed as {fraction of the configured
// range from floor (0.0) to 0dBFS (1.0), display %} pairs so the same
// curve shape applies whatever floor Settings -> Meter Range currently
// selects - see idleVUPct.
var idleVUCurve = [][2]float64{
	{0, 0}, {0.1667, 7}, {0.3333, 15}, {0.4444, 22}, {0.5556, 30}, {0.6667, 40},
	{0.7333, 48}, {0.8, 58}, {0.8667, 70}, {0.9, 78}, {0.9333, 85}, {0.9667, 92}, {1, 100},
}

func idleVUPct(db float64) float64 {
	floor := vuRangeOptions[vuRangeIdx]
	frac := (db - floor) / (0 - floor)
	if frac <= 0 {
		return idleVUCurve[0][1]
	}
	if frac >= 1 {
		return 100
	}
	for i := 1; i < len(idleVUCurve); i++ {
		if frac <= idleVUCurve[i][0] {
			lo, hi := idleVUCurve[i-1], idleVUCurve[i]
			t := (frac - lo[0]) / (hi[0] - lo[0])
			return lo[1] + t*(hi[1]-lo[1])
		}
	}
	return 100
}

// decayPeakHold applies peak-hold ballistics to meterChannelPeakHeld: a
// fresh instantaneous peak from meterReader always wins
// immediately, but a falling level holds at its peak for
// peakHoldOptions[peakHoldIdx] before decaying back down at a fixed
// ~20dB/s rate - the classic "peak lamp" behavior on a real meter, rather
// than the raw astats value jumping around every reset window. Ticked from
// peakHoldLoop every 100ms; callers must hold mutex.
func decayPeakHold() {
	n := len(meterChannelPeak)
	if n == 0 {
		meterChannelPeakHeld = nil
		peakHeldSetAt = nil
		return
	}
	if len(meterChannelPeakHeld) != n {
		meterChannelPeakHeld = append([]float64(nil), meterChannelPeak...)
		peakHeldSetAt = make([]time.Time, n)
		now := time.Now()
		for i := range peakHeldSetAt {
			peakHeldSetAt[i] = now
		}
		return
	}

	now := time.Now()
	hold := peakHoldOptions[peakHoldIdx]
	for i, instant := range meterChannelPeak {
		if instant >= meterChannelPeakHeld[i] {
			meterChannelPeakHeld[i] = instant
			peakHeldSetAt[i] = now
			continue
		}
		if hold == 0 || now.Sub(peakHeldSetAt[i]) > hold {
			meterChannelPeakHeld[i] -= 2.0 // 20dB/s at this loop's 100ms tick
			if meterChannelPeakHeld[i] < instant {
				meterChannelPeakHeld[i] = instant
			}
		}
	}
}

// peakHoldLoop runs decayPeakHold for the app's lifetime, independent of
// whether new astats samples are currently arriving - a real recording's
// peaks only update every astats reset window, but the display-facing
// held value needs to keep decaying smoothly in between those updates too.
func peakHoldLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		mutex.Lock()
		decayPeakHold()
		mutex.Unlock()
	}
}

// renderIdleBrowse dispatches to a VU-meter page or, once past the last
// one, the network/token page - see onEncoderRotate's StateIdleBrowse case
// for how idleBrowsePage cycles between them.
func renderIdleBrowse() {
	vuPages := idleVUPageCount()
	switch {
	case idleBrowsePage < vuPages:
		renderIdleVUPage(idleBrowsePage)
	case idleBrowsePage == vuPages:
		renderIdleWaveformPage()
	default:
		renderIdleInfoPage()
	}
}

// waveformCap bounds how many samples the scrolling waveform history keeps
// - one per render() tick (see pushWaveformSample), sized to just cover the
// panel's width so old samples fall off the left edge as new ones arrive
// on the right, like a real level-history scope trace.
const waveformCap = DisplayWidth - 4

var waveformHistory []float64

// pushWaveformSample appends the current loudest channel's instantaneous
// peak (or the overall meterPeakDB if no per-channel data exists, e.g.
// while idle-browse hasn't started a monitor) to the waveform history.
// Called from render() every tick regardless of which screen is showing,
// so the trace is already populated by the time someone pages to it rather
// than starting blank.
func pushWaveformSample() {
	level := meterPeakDB
	for _, v := range meterChannelPeak {
		if v > level {
			level = v
		}
	}
	waveformHistory = append(waveformHistory, level)
	if len(waveformHistory) > waveformCap {
		waveformHistory = waveformHistory[len(waveformHistory)-waveformCap:]
	}
}

// renderIdleWaveformPage draws the waveform history as a classic
// symmetric-around-center amplitude trace (like an audio editor's
// waveform), using the same log taper as the VU meters (idleVUPct) so a
// loud transient reads the same height here as it would as a VU deflection.
func renderIdleWaveformPage() {
	hwManager.SwitchToContext("details")
	hwManager.DrawText(2, 22, "Waveform")

	const top, bottom = 28, 54
	mid := (top + bottom) / 2
	halfH := (bottom - top) / 2

	hwManager.DrawBox(2, mid, waveformCap, 1, 4) // center baseline

	x := 2
	for _, db := range waveformHistory {
		h := int(idleVUPct(db) / 100 * float64(halfH))
		if h > 0 {
			hwManager.FillBox(x, mid-h, 1, 2*h+1, 12)
		}
		x++
	}

	hwManager.DrawText(2, 58, "Hold to return")
}

// renderIdleVUPage draws one page of up to idleVUChannelsPerPage input
// level meters, each as a vertical bar (RMS fill plus a peak-hold cap
// line) with a shared dB scale - explicitly including -12 and -40 markers
// - up the left edge. Entering idle-browse (see onEncoderRotate's StateIdle
// case) starts an input monitor if nothing else is already feeding
// meterChannelPeak/RMS, so these show live levels even before recording.
func renderIdleVUPage(page int) {
	pages := idleVUPageCount()
	// y=22 is the established safe first-content line elsewhere in this
	// file (see renderNetworkInfo etc.) - the status bar occupies the rows
	// above it, and drawing any earlier overlaps its text.
	hwManager.SwitchToContext("details")

	// Owner layout 2026-10-06: taller meters for more resolution, starting
	// 4px under the status bar (its lowest lit row is 11 - measured from
	// the framebuffer), and ending where the floor tick's label clears the
	// channel-number line at y=58.
	const statusBarBottom = 11
	const top, bottom = statusBarBottom + 1 + 4, 47
	const scaleW = 18
	barAreaX := scaleW
	barAreaW := DisplayWidth - barAreaX - 2

	// Ticks scale with the configured floor (Settings -> Meter Range)
	// rather than fixed values, always at 0, floor, and two points between.
	floor := vuRangeOptions[vuRangeIdx]
	for _, db := range []float64{0, -12, floor / 2, floor} {
		y := bottom - int(idleVUPct(db)/100*float64(bottom-top))
		// Baselines stay inside the meter area, so the 0 label does not
		// reach into the gap under the status bar.
		hwManager.DrawText(0, max(y+3, top+6), fmt.Sprintf("%d", int(db)))
		hwManager.DrawBox(scaleW-4, y, 4, 1, 10)
	}

	start := page * idleVUChannelsPerPage
	end := start + idleVUChannelsPerPage
	if end > channelCount {
		end = channelCount
	}
	n := end - start
	if n < 1 {
		n = 1
	}
	barW := barAreaW / n
	w := barW - 3
	if w < 6 {
		w = 6
	}

	for i := 0; i < n; i++ {
		ch := start + i
		x := barAreaX + i*barW
		rms, peak := meterSilence, meterSilence
		if ch < len(meterChannelRMS) {
			rms = meterChannelRMS[ch]
		}
		if ch < len(meterChannelPeakHeld) {
			peak = meterChannelPeakHeld[ch]
		}

		hwManager.DrawBox(x, top, w, bottom-top, 6)
		filledH := int(idleVUPct(rms) / 100 * float64(bottom-top))
		if filledH > 1 {
			hwManager.FillBox(x+1, bottom-filledH, w-2, filledH-1, 13)
		}
		peakY := bottom - int(idleVUPct(peak)/100*float64(bottom-top))
		hwManager.DrawBox(x+1, peakY, w-2, 1, 15)

		label := fmt.Sprintf("%d", ch+1)
		tw := hwManager.GetTextWidth(label)
		hwManager.DrawText(x+(w-tw)/2, 58, label)
	}
	// Under the scale: 16 bars fill the width, so the right edge is taken.
	ind := fmt.Sprintf("%d/%d", page+1, pages)
	hwManager.DrawText(0, 58, ind)
}

// renderIdleInfoPage is the page after the last VU meter: the same network
// details Settings -> Network Info shows, plus the remote-control access
// token (see remoteAccessInfo) for anyone who wants to hop on the WebUI
// after checking input levels here.
// infoPageCache avoids redoing interface enumeration, gateway/DNS reads and
// QR encoding at the 10Hz render tick while the info page is up: network
// facts change on DHCP/link timescales, and the QR only changes with IP,
// port or token. Guarded by the app mutex; render holds it.
var infoCache struct {
	at      time.Time
	details []string
	ip      string
	qrFor   string
	qr      [][]bool
}

const infoCacheTTL = 5 * time.Second

// accessQRURLLocked is the access QR's link: by mDNS name (owner rule:
// <device>.local, see mdnsaddr.go) while that name resolves, else by ip.
// The token rides in the fragment. Caller holds the mutex.
func accessQRURLLocked(ip string) string {
	host := mdnsURLHostLocked()
	if host == "" {
		host = ip
	}
	if p := remoteControlPort(); p != "80" { // the default needs no port (and a smaller QR)
		host += ":" + p
	}
	return "http://" + host + "/#t=" + remoteToken
}

func renderIdleInfoPage() {
	now := time.Now()
	if now.Sub(infoCache.at) > infoCacheTTL {
		infoCache.details = hwManager.Network.GetDetailedNetworkInfo()
		infoCache.ip = anyInterfaceIP()
		infoCache.at = now
	}
	details := infoCache.details
	hwManager.SwitchToContext("details")
	y := 22
	for i, d := range details {
		if i >= 2 {
			break
		}
		hwManager.DrawText(4, y, fitText(d, 190))
		y += 10
	}
	ip := infoCache.ip
	if ip != "" {
		key := accessQRURLLocked(ip)
		if infoCache.qrFor != key {
			infoCache.qr = qrBitmap(key)
			infoCache.qrFor = key
		}
		drawQRBitmapFit(infoCache.qr)
	} else {
		hwManager.DrawCenteredText("Token: "+formatToken(remoteToken), "selected", y+4)
	}
	hwManager.DrawCenteredText("Click or hold to return", "details", 58)
}

func renderRecordingScreen() {
	elapsed := time.Since(recordStart)
	remaining := estimateRemainingTime()
	storage := getRemainingStorage()

	// Use FiraCode's context-aware recording display with enhanced typography
	elapsedStr := formatDuration(elapsed)
	remainingStr := fmt.Sprintf("%s (%s)", formatDuration(remaining), storage)

	// When less than diskWarnMinutes of space remains at the current rate,
	// flash the two-line display on/off every half-second so a long take can't
	// quietly run out of room. On the blink phase the recording readout is
	// cleared and replaced by a "LOW DISK" tag (see below), so operators can
	// see the warning without losing the take.
	if cachedLowDisk() && time.Now().UnixMilli()/500%2 == 1 {
		hwManager.Clear()
	}

	// The third row shows the level meter rather than the filename while
	// recording - "am I getting signal" matters more during a live take
	// than the exact filename, and there's no vertical room on a 64px
	// display for a fourth line. The filename is still discoverable via
	// Copy Files, and is deterministic from the timestamp/settings already
	// shown elsewhere.
	hwManager.DrawRecordingStatus(elapsedStr, remainingStr, formatMeter())

	if cachedLowDisk() && time.Now().UnixMilli()/500%2 == 1 {
		// Overlay a flashing "LOW DISK" tag on the blink phase so the warning
		// is legible rather than the whole screen just turning off.
		hwManager.SwitchToContext("selected")
		hwManager.DrawText(8, 22, "LOW DISK")
	}
}

// formatMeter renders meterPeakDB/meterRMSDB (updated by meterReader off the
// recording ffmpeg's astats output - see startRecording) as a compact
// dB readout. Callers must hold mutex.
func formatMeter() string {
	if meterPeakDB <= meterSilence {
		return "Peak: -- RMS: --"
	}
	return fmt.Sprintf("Peak: %.1fdB  RMS: %.1fdB", meterPeakDB, meterRMSDB)
}

func renderPlayingScreen() {
	pos := playbackPosition()
	filename := ""
	if playbackFile != "" {
		filename = filepath.Base(playbackFile)
	}
	progress := 0.0
	if playbackDuration > 0 {
		progress = float64(pos) / float64(playbackDuration)
		if progress < 0 {
			progress = 0
		} else if progress > 1 {
			progress = 1
		}
	}
	hwManager.DrawPlaybackStatus(formatDuration(pos), formatDuration(playbackDuration), progress, filename, currentState == StatePaused)
}

// settingsLoggingRow is the Settings row of the in-place Logging setting.
const settingsLoggingRow = 3

// pendingLogLevel is the level shown while the Logging row is being edited;
// it applies only on the confirming press. Guarded by the app mutex.
var pendingLogLevel LogLevel

// loggingRowValue is the Logging row's value: the level being chosen while
// the row is edited, else the active level.
func loggingRowValue() string {
	if currentState == StateSettings && editingParameter && selectedMenu == settingsLoggingRow {
		return logLevelNames[int(pendingLogLevel)]
	}
	return logLevelNames[int(currentLogLevel())]
}

func renderSettingsMenu() {
	// No separate header: at 256x64 there isn't room for a title row above a
	// scrollable list without it colliding with either the status bar above
	// or the first item below, so the list starts right under the status bar.

	// Menu items using FiraCode MenuItem rendering. The top level carries
	// sub-menu entries and actions; multi-parameter groups live one level
	// down (Audio / Metering / Display / WiFi). A single-parameter setting
	// (Logging) is edited in place on its row instead of opening a page.
	allItems := []hardware.MenuItem{
		{Label: "Audio →", Value: fmt.Sprintf("WAV %dch", channelCount)},
		{Label: "Metering →", Value: fmt.Sprintf("%ddB", int(vuRangeOptions[vuRangeIdx]))},
		{Label: "Display →", Value: fmt.Sprintf("%d%%", oledBrightnessPct)},
		{Label: "Logging", Value: loggingRowValue()},
		{Label: "Copy Files →", Value: ""},
		{Label: "System Options →", Value: ""},
		{Label: "Network Info →", Value: ""},
		{Label: "Remote Access →", Value: ""},
		{Label: "Restart Inferno", Value: getInfernoStatusText()},
		{Label: "Monitoring", Value: map[bool]string{true: "on", false: "off"}[monitoring]},
		{Label: "WiFi →", Value: map[bool]string{true: "on", false: "off"}[wifiEnabled]},
		{Label: "Timecode →", Value: tcSourceNames[tcSourceIdx]},
		{Label: "Exit", Value: ""},
	}

	// Calculate scrolling parameters
	totalItems := len(allItems)
	maxVisibleItems := 4 // matches what actually fits below the status bar at this font size

	// Update scroll offset based on selected item
	if selectedMenu < menuScrollOffset {
		menuScrollOffset = selectedMenu
	} else if selectedMenu >= menuScrollOffset+maxVisibleItems {
		menuScrollOffset = selectedMenu - maxVisibleItems + 1
	}

	// Ensure scroll offset doesn't go past the end
	if menuScrollOffset > totalItems-maxVisibleItems {
		menuScrollOffset = totalItems - maxVisibleItems
	}
	if menuScrollOffset < 0 {
		menuScrollOffset = 0
	}

	// Create visible items slice
	endIdx := menuScrollOffset + maxVisibleItems
	if endIdx > totalItems {
		endIdx = totalItems
	}
	visibleItems := allItems[menuScrollOffset:endIdx]

	// Adjust selected index for visible items
	visibleSelectedIndex := selectedMenu - menuScrollOffset

	// Draw visible items
	y := 22
	fontHeight := 13

	for i, item := range visibleItems {
		// Switch to emphasis font for selected items
		if i == visibleSelectedIndex {
			if err := hwManager.SwitchToContext("selected"); err != nil {
				return
			}
		} else {
			if err := hwManager.SwitchToContext("menu"); err != nil {
				return
			}
		}

		prefix := "  "
		if i == visibleSelectedIndex {
			// "»" (editing this row's value now, rotate to adjust) vs ">"
			// (navigation cursor, rotate to move) - the two modes rotate
			// does very different things in, so the row needs to say which
			// one is active rather than leaving it to be discovered by trial.
			if editingParameter {
				prefix = "» "
			} else {
				prefix = "> "
			}
		}

		// Draw label
		labelText := prefix + item.Label
		hwManager.DrawText(8, y, labelText)

		// Draw right-aligned value if present
		if item.Value != "" {
			// Extra right margin (32, not 16) vs. the scroll-indicator
			// column: with several of these items carrying a value, any of
			// them can land as the top visible row when scrolled, so the up
			// arrow at (240,22) needs guaranteed clearance rather than
			// relying on empty-value rows happening to end up there.
			valueWidth := hwManager.GetTextWidth(item.Value)
			hwManager.DrawText(256-valueWidth-32, y, item.Value)
		}

		y += fontHeight
	}

	// Draw scroll indicators if needed
	if totalItems > maxVisibleItems {
		hwManager.SwitchToContext("details")
		// Up arrow if we can scroll up
		if menuScrollOffset > 0 {
			hwManager.DrawText(240, 22, "↑")
		}
		// Down arrow if we can scroll down
		if menuScrollOffset+maxVisibleItems < totalItems {
			hwManager.DrawText(240, 61, "↓")
		}
	}
}

// tagStatusText is the Settings-menu row value for "Tag".
func tagStatusText() string {
	if tagPresets[tagPresetIdx] == "" {
		return "None"
	}
	return tagPresets[tagPresetIdx]
}

// prefixStatusText is the OLED row value for "Prefix": the default prefix is
// shown as "Default" so it's clear the "" global means "not customized", and
// a set prefix is shown as-is.
func prefixStatusText() string {
	if filePrefix == "" {
		return "Default"
	}
	return filePrefix
}

// Get Inferno server status text for display
func getInfernoStatusText() string {
	switch infernoState {
	case InfernoRunning:
		return "Running"
	case InfernoStarting:
		return "Starting..."
	case InfernoFailed:
		return "Failed"
	default:
		return "Stopped"
	}
}

func renderCopyFilesMenu() {
	// No separate header - see renderSettingsMenu for why: at 256x64 there's
	// no room for a title row without it colliding with the list below it.

	// Create fixed menu items
	fixedMenuItems := []hardware.MenuItem{
		{Label: "▶ Start Copy", Value: ""},
		{Label: "☑ Select All", Value: fmt.Sprintf("(%d files)", len(allFiles))},
		{Label: "☐ Clear All", Value: ""},
	}

	// Calculate scrolling parameters for file list
	maxVisibleFiles := 1 // matches what actually fits below the 3 fixed items at this font size
	totalItems := len(fixedMenuItems) + len(allFiles)
	fixedItemsCount := len(fixedMenuItems)

	// Update scroll offset based on selected item
	if selectedMenu < menuScrollOffset {
		menuScrollOffset = selectedMenu
	} else if selectedMenu >= menuScrollOffset+fixedItemsCount+maxVisibleFiles {
		menuScrollOffset = selectedMenu - fixedItemsCount - maxVisibleFiles + 1
	}

	// Ensure scroll offset doesn't go past the end
	if menuScrollOffset > totalItems-fixedItemsCount-maxVisibleFiles {
		menuScrollOffset = totalItems - fixedItemsCount - maxVisibleFiles
	}
	if menuScrollOffset < 0 {
		menuScrollOffset = 0
	}

	// Draw fixed menu items first
	y := 22
	fontHeight := hwManager.GetFontHeight()

	for i, item := range fixedMenuItems {
		if selectedMenu == i {
			hwManager.SwitchToContext("selected")
		} else {
			hwManager.SwitchToContext("menu")
		}

		prefix := "  "
		if selectedMenu == i {
			prefix = "> "
		}

		labelText := prefix + item.Label
		hwManager.DrawText(8, y, labelText)

		if item.Value != "" {
			valueWidth := hwManager.GetTextWidth(item.Value)
			hwManager.DrawText(256-valueWidth-16, y, item.Value)
		}

		y += fontHeight
	}

	// Draw visible file items with scrolling
	fileStartIdx := 0
	if selectedMenu >= fixedItemsCount {
		fileOffset := selectedMenu - fixedItemsCount
		if fileOffset >= maxVisibleFiles {
			fileStartIdx = fileOffset - maxVisibleFiles + 1
		}
	}

	endIdx := fileStartIdx + maxVisibleFiles
	if endIdx > len(allFiles) {
		endIdx = len(allFiles)
	}

	for i := fileStartIdx; i < endIdx; i++ {
		file := allFiles[i]
		itemIndex := fixedItemsCount + i

		if selectedMenu == itemIndex {
			hwManager.SwitchToContext("selected")
		} else {
			hwManager.SwitchToContext("menu")
		}

		prefix := "  "
		if selectedMenu == itemIndex {
			prefix = "> "
		}

		checkbox := "[ ]"
		if filesToCopy[file] {
			checkbox = "[X]"
		}

		displayName := file
		maxTextWidth := DisplayWidth - 32 // Account for margins and checkbox
		if hwManager.GetTextWidth(prefix+checkbox+" "+displayName) > maxTextWidth {
			// Truncate filename if too long, rune-wise like fitText: byte
			// slicing would split multi-byte UTF-8 mid-sequence and render
			// as garbage.
			for len(displayName) > 0 && hwManager.GetTextWidth(prefix+checkbox+" "+displayName+"...") > maxTextWidth {
				_, size := utf8.DecodeLastRuneInString(displayName)
				displayName = displayName[:len(displayName)-size]
			}
			if len(displayName) > 0 {
				displayName = displayName + "..."
			}
		}

		hwManager.DrawText(8, y, fmt.Sprintf("%s%s %s", prefix, checkbox, displayName))
		y += fontHeight
	}

	// Draw scroll indicators if needed
	if len(allFiles) > maxVisibleFiles {
		hwManager.SwitchToContext("details")
		// Up arrow if we can scroll up
		if fileStartIdx > 0 {
			hwManager.DrawText(240, 50, "↑")
		}
		// Down arrow if we can scroll down
		if endIdx < len(allFiles) {
			hwManager.DrawText(240, 63, "↓")
		}
	}
}

func renderCopyProgress() {
	// Use FiraCode progress bar with enhanced typography
	title := "Copying to USB..."

	// Calculate estimated remaining time from wall-clock progress.
	remainingText := "Calculating..."
	if copyProgress > 0 {
		elapsed := time.Since(copyStarted)
		remaining := elapsed * time.Duration(100-copyProgress) / time.Duration(copyProgress)
		remainingText = "~" + remaining.Round(time.Minute).String() + " remaining"
	}

	// Folded into one line - a 64px display has no room for the bar,
	// percentage, remaining time, and a cancel hint as four separate rows.
	details := remainingText + " - hold 3s to cancel"

	hwManager.DrawProgressBar(title, float64(copyProgress), details)
}

// renderWifiMenu draws the WiFi access-point submenu (StateWifi): a tiny
// three-row list - Enable AP (on/off toggle), Show QR, Back. Reuses the
// same scrolling/menu logic pattern as renderSettingsMenu.
func renderWifiMenu() {
	items := []hardware.MenuItem{
		{Label: "WiFi AP →", Value: map[bool]string{true: "on", false: "off"}[wifiEnabled]},
		{Label: "WiFi QR →", Value: ""},
		{Label: "← Back", Value: ""},
	}
	totalItems := len(items)
	maxVisibleItems := 4

	if selectedMenu < menuScrollOffset {
		menuScrollOffset = selectedMenu
	} else if selectedMenu >= menuScrollOffset+maxVisibleItems {
		menuScrollOffset = selectedMenu - maxVisibleItems + 1
	}
	if menuScrollOffset > totalItems-maxVisibleItems {
		menuScrollOffset = totalItems - maxVisibleItems
	}
	if menuScrollOffset < 0 {
		menuScrollOffset = 0
	}

	endIdx := menuScrollOffset + maxVisibleItems
	if endIdx > totalItems {
		endIdx = totalItems
	}
	visibleItems := items[menuScrollOffset:endIdx]
	visibleSelectedIndex := selectedMenu - menuScrollOffset

	y := 22
	fontHeight := 13

	for i, item := range visibleItems {
		if i == visibleSelectedIndex {
			if err := hwManager.SwitchToContext("selected"); err != nil {
				return
			}
		} else {
			if err := hwManager.SwitchToContext("menu"); err != nil {
				return
			}
		}

		prefix := "  "
		if i == visibleSelectedIndex {
			prefix = "> "
		}

		labelText := prefix + item.Label
		hwManager.DrawText(8, y, labelText)

		if item.Value != "" {
			valueWidth := hwManager.GetTextWidth(item.Value)
			hwManager.DrawText(256-valueWidth-32, y, item.Value)
		}
		y += fontHeight
	}

	if totalItems > maxVisibleItems {
		hwManager.SwitchToContext("details")
		if menuScrollOffset > 0 {
			hwManager.DrawText(240, 22, "↑")
		}
		if menuScrollOffset+maxVisibleItems < totalItems {
			hwManager.DrawText(240, 61, "↓")
		}
	}
}

// renderAudioMenu draws the Audio submenu (StateAudio): Sample Rate, Channel
// Count, Tag, Back. Reuses the same scrolling/menu logic pattern as
// renderWifiMenu, with the editing-cursor prefix from renderSettingsMenu.
func renderAudioMenu() {
	items := []hardware.MenuItem{
		{Label: "Sample Rate →", Value: fmt.Sprintf("%dkHz", sampleRates[sampleRateIdx]/1000)},
		{Label: "Channel Count →", Value: fmt.Sprintf("%d", channelCount)},
		{Label: "Tag →", Value: tagStatusText()},
		{Label: "Prefix →", Value: prefixStatusText()},
		{Label: "TX", Value: txStatusShortLocked()},
		{Label: "RX Latency →", Value: rxLatencyStatusText()},
		{Label: "← Back", Value: ""},
	}
	renderEditableMenu(items)
}

// renderEditableMenu draws a submenu of press-to-edit rows (Audio,
// Timecode): four visible rows, scrolling, "»" on the row being edited.
func renderEditableMenu(items []hardware.MenuItem) {
	totalItems := len(items)
	maxVisibleItems := 4

	if selectedMenu < menuScrollOffset {
		menuScrollOffset = selectedMenu
	} else if selectedMenu >= menuScrollOffset+maxVisibleItems {
		menuScrollOffset = selectedMenu - maxVisibleItems + 1
	}
	if menuScrollOffset > totalItems-maxVisibleItems {
		menuScrollOffset = totalItems - maxVisibleItems
	}
	if menuScrollOffset < 0 {
		menuScrollOffset = 0
	}

	endIdx := menuScrollOffset + maxVisibleItems
	if endIdx > totalItems {
		endIdx = totalItems
	}
	visibleItems := items[menuScrollOffset:endIdx]
	visibleSelectedIndex := selectedMenu - menuScrollOffset

	y := 22
	fontHeight := 13

	for i, item := range visibleItems {
		if i == visibleSelectedIndex {
			if err := hwManager.SwitchToContext("selected"); err != nil {
				return
			}
		} else {
			if err := hwManager.SwitchToContext("menu"); err != nil {
				return
			}
		}

		prefix := "  "
		if i == visibleSelectedIndex {
			// "»" (editing this row's value now, rotate to adjust) vs ">"
			// (navigation cursor, rotate to move) - the two modes rotate
			// does very different things in, so the row needs to say which
			// one is active rather than leaving it to be discovered by trial.
			if editingParameter {
				prefix = "» "
			} else {
				prefix = "> "
			}
		}

		labelText := prefix + item.Label
		hwManager.DrawText(8, y, labelText)

		if item.Value != "" {
			valueWidth := hwManager.GetTextWidth(item.Value)
			hwManager.DrawText(256-valueWidth-32, y, item.Value)
		}
		y += fontHeight
	}

	if totalItems > maxVisibleItems {
		hwManager.SwitchToContext("details")
		if menuScrollOffset > 0 {
			hwManager.DrawText(240, 22, "↑")
		}
		if menuScrollOffset+maxVisibleItems < totalItems {
			hwManager.DrawText(240, 61, "↓")
		}
	}
}

// renderMeteringMenu draws the Metering submenu (StateMetering): Meter Range,
// Peak Hold, Back. Reuses the same scrolling/menu logic pattern as
// renderWifiMenu, with the editing-cursor prefix from renderSettingsMenu.
func renderMeteringMenu() {
	items := []hardware.MenuItem{
		{Label: "Meter Range →", Value: fmt.Sprintf("%ddB", int(vuRangeOptions[vuRangeIdx]))},
		{Label: "Peak Hold →", Value: peakHoldLabel()},
		{Label: "← Back", Value: ""},
	}
	totalItems := len(items)
	maxVisibleItems := 4

	if selectedMenu < menuScrollOffset {
		menuScrollOffset = selectedMenu
	} else if selectedMenu >= menuScrollOffset+maxVisibleItems {
		menuScrollOffset = selectedMenu - maxVisibleItems + 1
	}
	if menuScrollOffset > totalItems-maxVisibleItems {
		menuScrollOffset = totalItems - maxVisibleItems
	}
	if menuScrollOffset < 0 {
		menuScrollOffset = 0
	}

	endIdx := menuScrollOffset + maxVisibleItems
	if endIdx > totalItems {
		endIdx = totalItems
	}
	visibleItems := items[menuScrollOffset:endIdx]
	visibleSelectedIndex := selectedMenu - menuScrollOffset

	y := 22
	fontHeight := 13

	for i, item := range visibleItems {
		if i == visibleSelectedIndex {
			if err := hwManager.SwitchToContext("selected"); err != nil {
				return
			}
		} else {
			if err := hwManager.SwitchToContext("menu"); err != nil {
				return
			}
		}

		prefix := "  "
		if i == visibleSelectedIndex {
			// "»" (editing this row's value now, rotate to adjust) vs ">"
			// (navigation cursor, rotate to move) - the two modes rotate
			// does very different things in, so the row needs to say which
			// one is active rather than leaving it to be discovered by trial.
			if editingParameter {
				prefix = "» "
			} else {
				prefix = "> "
			}
		}

		labelText := prefix + item.Label
		hwManager.DrawText(8, y, labelText)

		if item.Value != "" {
			valueWidth := hwManager.GetTextWidth(item.Value)
			hwManager.DrawText(256-valueWidth-32, y, item.Value)
		}
		y += fontHeight
	}

	if totalItems > maxVisibleItems {
		hwManager.SwitchToContext("details")
		if menuScrollOffset > 0 {
			hwManager.DrawText(240, 22, "↑")
		}
		if menuScrollOffset+maxVisibleItems < totalItems {
			hwManager.DrawText(240, 61, "↓")
		}
	}
}

// renderDisplayMenu draws the Display submenu (StateDisplay): Brightness
// (0-100%), Auto Dim (On/Off) and Menu Timeout (Off/15s/30s/60s/2min) as
// press-to-edit rows plus Back - same interaction as the Audio/Metering
// parameter rows.
func renderDisplayMenu() {
	items := []hardware.MenuItem{
		{Label: "Brightness →", Value: fmt.Sprintf("%d%%", oledBrightnessPct)},
		{Label: "Auto Dim →", Value: map[bool]string{true: "On", false: "Off"}[autoDimEnabled]},
		{Label: "Menu Timeout →", Value: menuTimeoutLabel()},
		{Label: "← Back", Value: ""},
	}
	totalItems := len(items)
	maxVisibleItems := 4

	if selectedMenu < menuScrollOffset {
		menuScrollOffset = selectedMenu
	} else if selectedMenu >= menuScrollOffset+maxVisibleItems {
		menuScrollOffset = selectedMenu - maxVisibleItems + 1
	}
	if menuScrollOffset > totalItems-maxVisibleItems {
		menuScrollOffset = totalItems - maxVisibleItems
	}
	if menuScrollOffset < 0 {
		menuScrollOffset = 0
	}

	endIdx := menuScrollOffset + maxVisibleItems
	if endIdx > totalItems {
		endIdx = totalItems
	}
	visibleItems := items[menuScrollOffset:endIdx]
	visibleSelectedIndex := selectedMenu - menuScrollOffset

	y := 22
	fontHeight := 13

	for i, item := range visibleItems {
		if i == visibleSelectedIndex {
			if err := hwManager.SwitchToContext("selected"); err != nil {
				return
			}
		} else {
			if err := hwManager.SwitchToContext("menu"); err != nil {
				return
			}
		}

		prefix := "  "
		if i == visibleSelectedIndex {
			if editingParameter {
				prefix = "» "
			} else {
				prefix = "> "
			}
		}
		labelText := prefix + item.Label
		hwManager.DrawText(8, y, labelText)

		if item.Value != "" {
			valueWidth := hwManager.GetTextWidth(item.Value)
			hwManager.DrawText(256-valueWidth-32, y, item.Value)
		}
		y += fontHeight
	}

	if totalItems > maxVisibleItems {
		hwManager.SwitchToContext("details")
		if menuScrollOffset > 0 {
			hwManager.DrawText(240, 22, "↑")
		}
		if menuScrollOffset+maxVisibleItems < totalItems {
			hwManager.DrawText(240, 61, "↓")
		}
	}
}

func renderSystemOptionsMenu() { // No separate header - see renderSettingsMenu for why. 5 items don't all
	// fit at once either, so this scrolls the same way Settings does.
	items := []hardware.MenuItem{
		{Label: "Delete All Recordings", Value: ""},
		{Label: "Format USB Drive", Value: ""},
		{Label: "Export Config", Value: ""},
		{Label: "Import Config", Value: ""},
		{Label: "Shutdown System", Value: ""},
		{Label: "Restart System", Value: ""},
		{Label: "Demo Mode: " + map[bool]string{true: "On", false: "Off"}[demoMode], Value: ""},
		{Label: "← Exit", Value: ""},
	}

	totalItems := len(items)
	maxVisibleItems := 4

	if selectedMenu < menuScrollOffset {
		menuScrollOffset = selectedMenu
	} else if selectedMenu >= menuScrollOffset+maxVisibleItems {
		menuScrollOffset = selectedMenu - maxVisibleItems + 1
	}
	if menuScrollOffset > totalItems-maxVisibleItems {
		menuScrollOffset = totalItems - maxVisibleItems
	}
	if menuScrollOffset < 0 {
		menuScrollOffset = 0
	}

	endIdx := menuScrollOffset + maxVisibleItems
	if endIdx > totalItems {
		endIdx = totalItems
	}
	visibleItems := items[menuScrollOffset:endIdx]
	visibleSelectedIndex := selectedMenu - menuScrollOffset

	y := 22
	fontHeight := 13
	for i, item := range visibleItems {
		if i == visibleSelectedIndex {
			hwManager.SwitchToContext("selected")
		} else {
			hwManager.SwitchToContext("menu")
		}

		prefix := "  "
		if i == visibleSelectedIndex {
			prefix = "> "
		}
		hwManager.DrawText(8, y, prefix+item.Label)
		y += fontHeight
	}

	if totalItems > maxVisibleItems {
		hwManager.SwitchToContext("details")
		if menuScrollOffset > 0 {
			hwManager.DrawText(240, 22, "↑")
		}
		if menuScrollOffset+maxVisibleItems < totalItems {
			hwManager.DrawText(240, 61, "↓")
		}
	}
}

func renderConfirmDialog() {
	var title, message1, message2 string

	switch menuMode {
	case DeleteConfirm:
		title = "CONFIRM DELETE"
		message1 = "Delete ALL recordings?"
		message2 = "This action cannot be undone!"
	case FormatConfirm:
		title = "CONFIRM FORMAT"
		message1 = "Format USB drive?"
		message2 = "All data will be lost!"
	case ShutdownConfirm:
		title = "SHUTDOWN"
		message1 = "Power off the system?"
		message2 = ""
	case RestartConfirm:
		title = "RESTART"
		message1 = "Restart the system?"
		message2 = ""
	case InfernoRestartConfirm:
		title = "RESTART INFERNO"
		message1 = "Restart Inferno server?"
		message2 = "Will reconnect audio stream"
	case ConfigImportConfirm:
		title = "IMPORT CONFIG"
		message1 = "Import settings from USB?"
		message2 = "Overwrites current settings"
	}

	// Use FiraCode context-aware confirmation dialog
	selectedOption := 0 // NO is default (safer)
	if confirmOption == ConfirmYes {
		selectedOption = 1
	}

	hwManager.DrawConfirmationDialog(title, message1, message2, selectedOption)
}

func renderNetworkInfo() {
	// No separate header - see renderSettingsMenu for why.
	networkDetails := hwManager.Network.GetDetailedNetworkInfo()

	y := 22
	maxLines := 3 // Limit to fit above the footer line
	for i, detail := range networkDetails {
		if i >= maxLines {
			break
		}

		// Use different contexts for different types of info. "selected"
		// (bold but same point size as neighbors) highlights the connected
		// status without the layout jump "emphasis" causes at its 16pt size.
		context := "details"
		if i == 0 { // Interface name
			context = "menu"
		} else if strings.Contains(detail, "Status:") {
			if strings.Contains(detail, "Connected") {
				context = "selected"
			} else {
				context = "details"
			}
		}

		hwManager.DrawCenteredText(detail, context, y)
		y += 11
	}

	// Add back instruction
	hwManager.DrawCenteredText("Hold encoder to return", "details", 58)
}

func renderRemoteInfo() {
	// No separate header - see renderSettingsMenu for why.
	lines := remoteAccessInfo()

	y := 22
	for i, line := range lines {
		context := "details"
		if i == 0 {
			context = "menu"
		}
		hwManager.DrawCenteredText(line, context, y)
		y += 11
	}

	hwManager.DrawCenteredText("Hold encoder to return", "details", 58)
}
