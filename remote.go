package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
	"golang.org/x/net/websocket"

	"pi9696/hardware"
)

// remoteToken gates every route except /login. It's generated fresh at each
// process startup (never persisted to disk), printed to the journal, and shown on the OLED via
// Settings -> Remote Access, so reading it requires physical/console access
// to the device - the same trust model as the rest of this app's local-only
// controls, just extended to the LAN.
//
// It's short (8 chars from a 31-symbol alphabet, ~39.6 bits of entropy)
// because it has to fit on a 256px-wide OLED line and be typeable from a
// phone; loginLimiter's lockout is what keeps that from being brute-forceable
// over the network in practice, not the raw length. Displayed (OLED, login
// page) as two groups of 4 for readability - see formatToken.
var remoteToken string

const (
	remoteTokenLength   = 8
	remoteTokenAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ" // Crockford-style, no 0/O/1/I/L - avoids exactly the characters most likely to be misread on a small OLED
)

func generateRemoteToken() string {
	// Rejection sampling: 256 is not a multiple of the 31-symbol alphabet,
	// so a plain byte%31 made the first 8 symbols slightly likelier. Bytes
	// at or above the largest multiple of 31 are discarded and redrawn.
	limit := 256 - 256%len(remoteTokenAlphabet)
	out := make([]byte, 0, remoteTokenLength)
	b := make([]byte, remoteTokenLength*2)
	for len(out) < remoteTokenLength {
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("Failed to generate remote control token: %v", err)
		}
		for _, c := range b {
			if int(c) < limit && len(out) < remoteTokenLength {
				out = append(out, remoteTokenAlphabet[int(c)%len(remoteTokenAlphabet)])
			}
		}
	}
	return string(out)
}

// generateRemoteSessionID produces the cookie value: a longer, full-entropy
// hex string, not the short operator-typed token. It's never shown to the
// user and never equals the token, so a session cookie can't be guessed from
// the token (and vice versa).
func generateRemoteSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// formatToken renders a token as two groups of 4 for readability, e.g.
// "K7M2QX9F" -> "K7M2 QX9F". Display-only - the raw unseparated string is
// what's actually stored/compared.
func formatToken(t string) string {
	if len(t) != remoteTokenLength {
		return t
	}
	return t[:4] + " " + t[4:]
}

// normalizeToken strips whatever separator a user typed between the two
// groups, so "K7M2 QX9F", "K7M2-QX9F", and "K7M2QX9F" all compare equal.
// Uppercased first: the alphabet is uppercase-only, so a lowercase direct
// POST (curl, QR #t= URL typed by hand) must not 401.
func normalizeToken(s string) string {
	return strings.NewReplacer(" ", "", "-", "").Replace(strings.ToUpper(s))
}

const remoteSessionCookie = "pi9696_session"

// loginLimiter blunts online guessing of the short token: 5 failed attempts
// from an IP locks that IP out for a minute. Deliberately separate from the
// app's UI mutex - this only ever guards its own map, never app state.
//
// Its maps are keyed by source address, which a LAN attacker with many
// addresses controls, so they are bounded: at most loginMaxTracked
// addresses are tracked, and the stale-entry sweep runs at most once per
// loginSweepEvery instead of on every attempt.
type loginLimiter struct {
	mu        sync.Mutex
	failures  map[string]int
	lockedAt  map[string]time.Time
	seenAt    map[string]time.Time
	lastSweep time.Time
}

// loginMaxTracked caps the addresses the limiter remembers. A new address
// arriving at the cap is refused (fail closed) rather than evicting an old
// one, which would hand a locked-out attacker a fresh allowance; the cap
// drains as the sweep expires idle entries a minute later.
const loginMaxTracked = 4096

// loginSweepEvery throttles the O(n) stale-entry sweep, so a flood of
// attempts costs one sweep a second, not one per attempt.
const loginSweepEvery = time.Second

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{failures: make(map[string]int), lockedAt: make(map[string]time.Time), seenAt: make(map[string]time.Time)}
}

func (l *loginLimiter) allowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if until, ok := l.lockedAt[ip]; ok {
		if time.Since(until) < 60*time.Second {
			return false
		}
		delete(l.lockedAt, ip)
		delete(l.failures, ip)
	}
	// Sweep stale entries: sessions.create prunes its own map, but
	// probed-never-locked IPs would otherwise grow these maps forever.
	// Expired lockouts go too, or an address that never returns would
	// hold its slot against loginMaxTracked forever.
	if now := time.Now(); now.Sub(l.lastSweep) >= loginSweepEvery {
		l.lastSweep = now
		for probe, at := range l.seenAt {
			if now.Sub(at) < 60*time.Second {
				continue
			}
			if locked, ok := l.lockedAt[probe]; ok && now.Sub(locked) < 60*time.Second {
				continue
			}
			delete(l.seenAt, probe)
			delete(l.failures, probe)
			delete(l.lockedAt, probe)
		}
	}
	if _, known := l.seenAt[ip]; !known && len(l.seenAt) >= loginMaxTracked {
		return false
	}
	// Reserve the attempt here, in the same critical section as the
	// check. Counting only on failure let a burst of N concurrent POSTs all
	// pass this check before any failure was recorded: N guesses per
	// lockout window instead of loginMaxAttempts. A success clears the
	// reservation (recordSuccess).
	if l.failures[ip] >= loginMaxAttempts {
		l.lockedAt[ip] = time.Now()
		return false
	}
	l.failures[ip]++
	l.seenAt[ip] = time.Now()
	return true
}

// loginMaxAttempts is how many login attempts an address gets before a
// minute's lockout.
const loginMaxAttempts = 5

// recordFailure closes a failed attempt that allowed already counted; the
// last permitted one starts the lockout.
func (l *loginLimiter) recordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seenAt[ip] = time.Now()
	if l.failures[ip] >= loginMaxAttempts {
		l.lockedAt[ip] = time.Now()
	}
}

func (l *loginLimiter) recordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, ip)
	delete(l.lockedAt, ip)
	delete(l.seenAt, ip)
}

var loginLimit = newLoginLimiter()

// sessionStore holds issued session IDs with their expiry. It is deliberately
// a separate in-memory store (not the token itself): the login token is the
// secret the operator reads off the OLED and types in, and it never becomes
// the cookie value. Instead, a fresh random session ID is minted at login and
// stored here with a lifetime, so (a) the cookie doesn't carry the token, and
// (b) sessions actually expire server-side - the browser's MaxAge alone only
// tells the client when to drop the cookie, not the server when to stop
// accepting it. A process restart clears all sessions (fresh token + empty
// store), which is acceptable for a device that re-logs-in after a reboot.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time // session ID -> expiry
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]time.Time)}
}

// create mints a new session ID valid for the given lifetime. Each login
// also sweeps out every already-expired entry: valid() only prunes lazily,
// when the same expired ID is presented again, so entries that expire and
// are never re-presented would otherwise sit in the map forever on this
// long-running device. Sweeping here bounds the map to (live sessions +
// logins since the last login) with no extra timer.
func (s *sessionStore) create(ttl time.Duration) string {
	id, err := generateRemoteSessionID()
	if err != nil {
		// Session IDs use the same crypto/rand source as the token; a failure
		// here is fatal (there's no safe fallback for a bearer credential).
		log.Fatalf("Failed to generate session ID: %v", err)
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, k)
		}
	}
	s.sessions[id] = now.Add(ttl)
	return id
}

// valid reports whether id is a live, unexpired session. Expired entries are
// pruned lazily here when they're presented again; entries that expire and
// are never re-presented are swept by the next login (see create).
func (s *sessionStore) valid(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[id]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.sessions, id)
		return false
	}
	return true
}

// revoke removes a session (logout), so a logged-out cookie can't be replayed.
func (s *sessionStore) revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// revokeAll drops every session: used by token rotation so sessions minted
// under a compromised token don't survive it (logout alone revokes only the
// presented cookie).
func (s *sessionStore) revokeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = make(map[string]time.Time)
}

var sessions = newSessionStore()

// sessionLifetime is how long a login session lasts server-side.
const sessionLifetime = 12 * time.Hour

// clientIP is the address the login limiter keys on. Normally the TCP
// peer. When the peer is a reverse proxy listed in PI9696_TRUSTED_PROXIES
// (both units sit behind one), every client would otherwise share the
// proxy's address, so five bad tokens from anyone locked everyone out for
// a minute, repeatably. For a trusted peer the client is the rightmost
// X-Forwarded-For entry that is not itself a trusted proxy (entries to its
// left are client-supplied and spoofable). Untrusted peers' headers are
// ignored, so the default - no list - is the old behaviour.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !isTrustedProxy(host) {
		return host
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if _, err := netip.ParseAddr(hop); err != nil {
			break // malformed chain: trust nothing further left
		}
		if !isTrustedProxy(hop) {
			return hop
		}
	}
	return host
}

// trustedProxies parses PI9696_TRUSTED_PROXIES once: comma-separated
// addresses or CIDR prefixes of reverse proxies whose X-Forwarded-For may
// be believed. A var so tests can substitute a list.
var trustedProxies = sync.OnceValue(func() []netip.Prefix {
	list, bad := parseTrustedProxies(os.Getenv("PI9696_TRUSTED_PROXIES"))
	for _, b := range bad {
		logErrorf("PI9696_TRUSTED_PROXIES: ignoring %q (not an address or CIDR prefix)", b)
	}
	return list
})

// parseTrustedProxies returns the valid prefixes in s (a bare address is a
// single-address prefix) and the entries it could not parse.
func parseTrustedProxies(s string) (list []netip.Prefix, bad []string) {
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			list = append(list, p.Masked())
		} else if a, err := netip.ParseAddr(f); err == nil {
			list = append(list, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		} else {
			bad = append(bad, f)
		}
	}
	return list, bad
}

func isTrustedProxy(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range trustedProxies() {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// validSession checks the cookie against the server-side session store (a
// constant-time lookup isn't needed here - sessions are random IDs looked up
// in a map, not a secret compared byte-by-byte).
func validSession(r *http.Request) bool {
	c, err := r.Cookie(remoteSessionCookie)
	if err != nil {
		return false
	}
	return sessions.valid(c.Value)
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validSession(r) {
			// WS handshakes and API/fetch callers can't follow a 303
			// (handshake just fails, <img> renders login HTML): give
			// them a 401 they can act on instead.
			if strings.HasPrefix(r.URL.Path, "/ws/") || strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "session expired", http.StatusUnauthorized)
				return
			}
			// Redirect bare, without the query: the access-QR prefill token
			// travels in the fragment (/#t=...), which browsers preserve
			// across this 303 and never send to the server - keeping it
			// out of server and proxy logs and the login POST (it does
			// stay in the browser's own history).
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// Mutations and WS handshakes additionally need a same-origin
		// request: the cookie is SameSite=Strict, but old/non-conforming
		// clients and x/net/websocket's default-accept handshake don't
		// honor that, and a foreign page driving an authenticated browser
		// is exactly the CSRF shape.
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions ||
			strings.HasPrefix(r.URL.Path, "/ws/") {
			if !checkSameOrigin(r) {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

// checkSameOrigin reports whether a request's Origin (or Referer fallback)
// matches the request's own host. Absent headers (curl, tests, same-origin
// navigations) pass - this is defense in depth behind SameSite=Strict, not
// a boundary: it stops conforming browsers (which always send Origin on
// POST/WS) from driving the device cross-origin.
func checkSameOrigin(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	}
	return true
}

// pi9696LogoSVG is a small inline vector wordmark shared by the login and
// dashboard pages - a chrome-gradient italic wordmark with speed-line
// flourishes and thin accent bars, styled after 1980s corporate logotypes
// (Tandy/Compaq/NBC-era). An inline SVG needs no raster asset shipped or
// fetched, which matters on a device that has to work with no internet
// access, and it scales cleanly from the login page's large mark down to
// the dashboard header's small one.
const pi9696LogoSVG = `<svg class="logo-svg" viewBox="0 0 320 110" xmlns="http://www.w3.org/2000/svg">
<defs>
<linearGradient id="chrome" x1="0" y1="0" x2="0" y2="1">
<stop offset="0%" stop-color="#eafcff"/><stop offset="30%" stop-color="#00d9ff"/>
<stop offset="70%" stop-color="#0066ff"/><stop offset="100%" stop-color="#021a33"/>
</linearGradient>
<linearGradient id="bar" x1="0" y1="0" x2="1" y2="0">
<stop offset="0%" stop-color="#0066ff" stop-opacity="0"/><stop offset="50%" stop-color="#00d9ff"/>
<stop offset="100%" stop-color="#0066ff" stop-opacity="0"/>
</linearGradient>
</defs>
<g stroke="#123a52" stroke-width="1.5" opacity="0.7">
<line x1="4" y1="96" x2="70" y2="80"/><line x1="4" y1="104" x2="86" y2="88"/>
<line x1="316" y1="96" x2="250" y2="80"/><line x1="316" y1="104" x2="234" y2="88"/>
</g>
<rect x="30" y="24" width="260" height="2" fill="url(#bar)"/>
<text x="160" y="72" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-size="52" font-weight="900" font-style="italic" fill="url(#chrome)" textLength="260" lengthAdjust="spacingAndGlyphs">PI9696</text>
<rect x="30" y="82" width="260" height="2" fill="url(#bar)"/>
<text x="160" y="102" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-size="10" fill="#5b8aa8" textLength="260" lengthAdjust="spacingAndGlyphs">MULTITRACK RECORDER</text>
</svg>`

// pi9696IconSVG is the PWA/home-screen icon - a square mark reusing the
// dashboard's reel-hub motif (see the .reel SVGs in dashboardTmpl) rather
// than inventing a second visual language just for the icon. Served as-is
// (image/svg+xml): every modern mobile browser that supports "Add to Home
// Screen" for a PWA accepts an SVG manifest icon, so no PNG rasterizer
// dependency is needed.
const pi9696IconSVG = `<svg viewBox="0 0 192 192" xmlns="http://www.w3.org/2000/svg">
<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
<stop offset="0%" stop-color="#00d9ff"/><stop offset="100%" stop-color="#0066ff"/>
</linearGradient></defs>
<rect width="192" height="192" rx="34" fill="#020509"/>
<circle cx="96" cy="96" r="74" fill="none" stroke="url(#g)" stroke-width="6"/>
<g fill="none" stroke="url(#g)" stroke-width="6">
<path d="M96 96 L68 40 Q96 24 124 40 Z" transform="rotate(0 96 96)"/>
<path d="M96 96 L68 40 Q96 24 124 40 Z" transform="rotate(120 96 96)"/>
<path d="M96 96 L68 40 Q96 24 124 40 Z" transform="rotate(240 96 96)"/>
</g>
<circle cx="96" cy="96" r="17" fill="url(#g)"/>
</svg>`

func handleIcon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	fmt.Fprint(w, pi9696IconSVG)
}

// manifestTmpl is static JSON with the device name filled in so an installed
// home-screen icon reflects a renamed unit without a rebuild. Rendered with
// encoding/json (not html/template): the name validator excludes
// JSON-significant chars today, but the wrong engine invites a future break.
func handleManifest(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	name := deviceName
	mutex.Unlock()
	w.Header().Set("Content-Type", "application/manifest+json")
	manifest := map[string]any{
		"name":             name + " Remote",
		"short_name":       name,
		"start_url":        "/",
		"display":          "standalone",
		"background_color": "#020509",
		"theme_color":      "#00d9ff",
		"icons":            []map[string]string{{"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any"}},
	}
	// start_url ("/") requires auth like every other route - opening the
	// installed app when the session cookie has expired just lands on
	// /login, same as any bookmark would.
	if err := json.NewEncoder(w).Encode(manifest); err != nil {
		logDebugf("manifest encode: %v", err)
	}
}

type loginPageData struct {
	Error, DeviceName string
	Logo              template.HTML
	// Theme/ThemeCSS mirror the dashboard's opt-in theming so the login
	// page is the same product, not a stranger: data-theme scopes the
	// design tokens (e.g. --font) the stylesheet reads. Unthemed
	// renders exactly as before (no marker beyond "none", no href).
	// CoreVersion cache-busts the always-linked core.css.
	Theme, ThemeCSS, CoreVersion string
	// HTMLTag is the prebuilt <html> open tag carrying data-theme and the
	// library display options (motion/contrast/density).
	HTMLTag template.HTML
	// Boxes pre-fills the 8 token inputs so a failed attempt (or a QR
	// prefill) isn't wiped by the error re-render.
	Boxes [8]string
}

// boxesFromToken splits a normalized token into per-box characters.
func boxesFromToken(t string) (b [8]string) {
	for i, c := range t {
		if i >= 8 {
			break
		}
		b[i] = string(c)
	}
	return b
}

// loginPageTheme returns the dashboard's active theme for the login page.
func loginPageTheme() (string, string) {
	active := currentTheme()
	return active, themeCSSHref(active)
}

var loginPageTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
{{.HTMLTag}}<head><title>{{.DeviceName}} Remote</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="manifest" href="/manifest.json">
<link rel="icon" href="/icon.svg" type="image/svg+xml">
<!-- Core is always linked (reset + shared components, no tokens of its own);
   the active theme bundle on top supplies the palette. -->
<link rel="stylesheet" href="/static/themes/core.css?v={{.CoreVersion}}">
<link rel="stylesheet" href="{{.ThemeCSS}}">
<style>
body{font-family:var(--font,"Consolas",monospace);background:radial-gradient(ellipse at center,var(--surface,#0a1a2e),var(--bg,#020509) 75%);color:var(--text,#cfeeff);display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;gap:2em}
.logo-svg{width:480px;max-width:85vw;display:block}
/* Box geometry is the shared .panel; the centered layout is app-owned. */
form.panel{text-align:center;min-width:20em}
.token-row{display:flex;align-items:center;justify-content:center;gap:var(--space-2xs,0.4em);margin-bottom:var(--space-m,1em)}
.token-row .input{font-size:1.3em;width:1.4em;padding:0.4em 0;text-align:center;text-transform:uppercase}
.token-row .dash{color:var(--muted,#5b8aa8);font-size:1.3em}
.err{color:var(--danger,#ff3355)}
.hint{color:var(--muted,#5b8aa8);font-size:0.85em;margin-top:1em}

@media (max-width: 480px) {
  form.panel{padding:1.5em 1.2em}
  .token-row{gap:0.25em}
  .token-row .input{width:1.1em;font-size:1.1em}
}
</style></head>
<body>
{{.Logo}}
<form method="POST" action="/login" id="loginForm" class="panel">
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<div class="token-row" id="tokenRow">
<input class="input" maxlength="1" autofocus autocomplete="off" value="{{index .Boxes 0}}">
<input class="input" maxlength="1" autocomplete="off" value="{{index .Boxes 1}}">
<input class="input" maxlength="1" autocomplete="off" value="{{index .Boxes 2}}">
<input class="input" maxlength="1" autocomplete="off" value="{{index .Boxes 3}}">
<span class="dash">-</span>
<input class="input" maxlength="1" autocomplete="off" value="{{index .Boxes 4}}">
<input class="input" maxlength="1" autocomplete="off" value="{{index .Boxes 5}}">
<input class="input" maxlength="1" autocomplete="off" value="{{index .Boxes 6}}">
<input class="input" maxlength="1" autocomplete="off" value="{{index .Boxes 7}}">
</div>
<input type="hidden" name="token" id="tokenValue">
<noscript><p><input name="token" maxlength="9" autocomplete="off" placeholder="XXXXXXXX" style="text-transform:uppercase"></p></noscript>
<button type="submit" class="btn btn-primary">Enter</button>
<p class="hint">8-character code shown on the OLED (Settings &rarr; Remote Access)</p>
</form>
<script>
// One box per character, auto-advancing focus, joined into the hidden
// "token" field the existing /login handler already expects (it strips
// separators itself via normalizeToken, so the dash here is display-only).
var boxes = document.querySelectorAll('#tokenRow input');
boxes.forEach(function(box, i) {
  box.addEventListener('input', function() {
    box.value = box.value.toUpperCase();
    if (box.value && i < boxes.length - 1) boxes[i + 1].focus();
  });
  box.addEventListener('keydown', function(e) {
    if (e.key === 'Backspace' && !box.value && i > 0) boxes[i - 1].focus();
  });
  box.addEventListener('paste', function(e) {
    e.preventDefault();
    var chars = (e.clipboardData.getData('text') || '').replace(/[^A-Za-z0-9]/g, '').toUpperCase().split('');
    for (var j = 0; j < chars.length && i + j < boxes.length; j++) boxes[i + j].value = chars[j];
    boxes[Math.min(i + chars.length, boxes.length - 1)].focus();
  });
});
// The OLED's access-QR encodes a URL with "#t=<token>"; pre-fill the boxes
// so scanning the code lands the operator one click from Enter. The fragment
// is never sent to the server, so unlike the old ?t= query it stays out of
// browser history and proxy logs.
(function() {
  var m = /[#&?]t=([A-Za-z0-9]{8})/.exec(window.location.hash);
  var t = m && m[1];
  if (t) {
    t = t.toUpperCase();
    for (var j = 0; j < t.length; j++) boxes[j].value = t[j];
    boxes[boxes.length - 1].focus();
  }
})();
document.getElementById('loginForm').addEventListener('submit', function() {
  document.getElementById('tokenValue').value = Array.from(boxes).map(function(b) { return b.value; }).join('');
});
</script>
</body></html>`))

func handleLoginGet(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	// Only start the show-token window if it isn't already running: a
	// crawler/attacker GETting /login in a loop must not extend it (the
	// token would stay parked on the panel indefinitely).
	if !loginTokenFreshLocked() {
		lastLoginPage = time.Now()
	}
	mutex.Unlock()
	writeLoginPage(w, loginPageData{})
}

// writeLoginPage fills in the page-invariant fields (name, logo, theme) and
// renders; error/box state rides in d.
// renderFragment executes a page or htmx fragment template into the
// response. These calls used to drop the error: a failing template sent a
// truncated 200 with nothing logged. Headers are usually already sent by
// then, so the error can only be logged, but now it always is.
func renderFragment(w io.Writer, t *template.Template, data any) {
	if err := t.Execute(w, data); err != nil {
		logErrorf("render %s: %v", t.Name(), err)
	}
}

// frag renders a fragment for embedding in a page template.
func frag(t *template.Template, data any) template.HTML {
	var b bytes.Buffer
	renderFragment(&b, t, data)
	return template.HTML(b.String())
}

func writeLoginPage(w http.ResponseWriter, d loginPageData) {
	// Snapshot under the app mutex: a WebUI rename writes deviceName under
	// it, and reading a string mid-write is a data race. No caller holds the
	// mutex here (loginPageTheme below takes it too).
	mutex.Lock()
	d.DeviceName = deviceName
	mutex.Unlock()
	d.Logo = template.HTML(pi9696LogoSVG)
	d.Theme, d.ThemeCSS = loginPageTheme()
	d.CoreVersion = themeBuildVersion()
	d.HTMLTag = displayHTMLTag(currentTheme(), currentThemeVariant(), currentThemeTint(currentTheme()))
	if err := loginPageTmpl.Execute(w, d); err != nil {
		logDebugf("login render: %v", err)
	}
}

func handleLoginPost(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !loginLimit.allowed(ip) {
		w.WriteHeader(http.StatusTooManyRequests)
		writeLoginPage(w, loginPageData{Error: "Too many attempts, wait a minute"})
		return
	}

	submitted := normalizeToken(r.FormValue("token"))
	// Rotation writes remoteToken under the app mutex; reading it bare here
	// raced with that write.
	mutex.Lock()
	token := remoteToken
	mutex.Unlock()
	if subtle.ConstantTimeCompare([]byte(submitted), []byte(token)) != 1 {
		loginLimit.recordFailure(ip)
		w.WriteHeader(http.StatusUnauthorized)
		writeLoginPage(w, loginPageData{Error: "Invalid token", Boxes: boxesFromToken(submitted)})
		return
	}

	loginLimit.recordSuccess(ip)
	// Mint a fresh session ID; the cookie value is never the token.
	sessionID := sessions.create(sessionLifetime)
	http.SetCookie(w, &http.Cookie{
		Name:     remoteSessionCookie,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// No Secure flag: this server is plain HTTP (see README's Auth &
		// Security notes for why, and what that means for LAN
		// eavesdropping risk). The server-side lifetime is enforced by
		// sessionStore.valid, not this client-side MaxAge.
		MaxAge: int(sessionLifetime / time.Second),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	// Revoke server-side so a captured cookie can't be replayed after logout.
	if c, err := r.Cookie(remoteSessionCookie); err == nil {
		sessions.revoke(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: remoteSessionCookie, Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleAPIRotateToken mints a fresh access token and revokes every session
// (including the caller's): sessions from a compromised token must not
// survive rotation. Redirects to /login with the new token in the fragment,
// so the operator's boxes pre-fill and they're one click from logging back
// in - while the token itself never touches a query string or the server log.
func handleAPIRotateToken(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	remoteToken = generateRemoteToken()
	sessions.revokeAll()
	noteActivity()
	newToken := remoteToken
	mutex.Unlock()
	logInfof("access token rotated, all sessions revoked")
	fmt.Fprintln(os.Stderr, "remote access code (rotated):", formatToken(newToken))
	http.SetCookie(w, &http.Cookie{Name: remoteSessionCookie, Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login#t="+newToken, http.StatusSeeOther)
}

// --- Themes ---------------------------------------------------------------
//
// The dashboard reads ftl-themes' tokens directly (--accent, --surface,
// --text, --muted, --danger, --success, --warning, --space-*). Selecting a
// theme links one self-contained bundle that defines them, so every rule
// re-colours with no rule needing editing; the app also re-lays-out the page
// through the library's app-shell hooks.
//
// v4 dropped the ftl- prefix from every token, so the app deliberately
// declares none of them itself: core.css already supplies the baseline set,
// and a same-named declaration would silently override the theme (or, for
// --text/--border, become self-referential and resolve to nothing).
// TestDefaultThemeIsFTL enforces that.

// defaultThemeSlug is the ftl-themes bundle a fresh or upgraded unit links:
// xbmc's blue-on-navy is the closest shipping palette to the old built-in
// look. blue-future (the baseline sci-fi HUD this dashboard was extracted
// from) takes over once upstream un-archives it - see ftl-themes#49.
const defaultThemeSlug = "xbmc"

// themeSlug names the bundle the dashboard links. Persisted in the unit's
// config like every other setting, so the choice follows the device rather
// than one browser. Guarded by mutex.
var themeSlug = defaultThemeSlug

// themeVariant is the palette variant (CONTRACT.md "Palette variants") of
// themeSlug, rendered as <html data-variant>; "" is the theme's own palette.
// Persisted beside the theme and only ever one the theme lists. Guarded by
// mutex.
var themeVariant string

// themeTints is the user-chosen tint colour per theme slug (CONTRACT.md
// "Theme tint"): only themes whose manifest declares a tint, only #rrggbb.
// Absent means the theme's default or the chosen preset shows. Guarded by
// mutex.
var themeTints = map[string]string{}

var tintColorRE = regexp.MustCompile(`^#[0-9a-f]{6}$`)

// normalizeTint returns a colour as lowercase #rrggbb, or "" if it isn't one.
func normalizeTint(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if !tintColorRE.MatchString(v) {
		return ""
	}
	return v
}

// validThemeTints keeps the entries of a loaded map that name a theme with
// a tint and hold a valid colour.
func validThemeTints(in map[string]string) map[string]string {
	out := map[string]string{}
	for slug, v := range in {
		if themeTintSpec(slug) != nil {
			if c := normalizeTint(v); c != "" {
				out[slug] = c
			}
		}
	}
	return out
}

// themeTintSpec returns a theme's tint declaration, nil if it has none.
func themeTintSpec(slug string) *themeTintEntry {
	for _, t := range availableThemes() {
		if t.Slug == slug {
			return t.Tint
		}
	}
	return nil
}

// currentThemeTint returns the stored tint colour for slug, "" when none
// is stored or the theme declares no tint (a tint is never rendered for a
// theme without one).
func currentThemeTint(slug string) string {
	if themeTintSpec(slug) == nil {
		return ""
	}
	mutex.Lock()
	defer mutex.Unlock()
	return themeTints[slug]
}

// tintTokens lists every tint token the manifest declares, so a theme
// change can remove the previous theme's inline token.
func tintTokens() []string {
	var out []string
	for _, t := range availableThemes() {
		if t.Tint != nil {
			out = append(out, t.Tint.Token)
		}
	}
	return out
}

// Library display options (CONTRACT.md "User display options"): browser
// switches an app may offer beside the theme, applied as documentElement
// attributes/style. Guarded by the app mutex; persisted like every setting.
var (
	displayMotion     = "full"     // or "reduced" -> <html data-motion="reduced">
	displayContrast   = "standard" // or "high"    -> <html data-contrast="high">
	displayDensityIdx = 0          // 0 Normal, 1 Compact (0.85), 2 Comfortable (1.15)
)

var displayDensityValues = [3]string{"1", "0.85", "1.15"}

// displayHTMLTag renders the whole <html> open tag: data-theme plus the
// library display options (attributes only when non-default, density as an
// inline custom property - the contract's documented override path, which
// beats any theme). Built server-side because html/template refuses
// dynamic content between a tag's attributes.
func displayHTMLTag(theme, variant, tint string) template.HTML {
	mutex.Lock()
	motion, contrast, density := displayMotion, displayContrast, displayDensityValues[displayDensityIdx]
	mutex.Unlock()
	var b strings.Builder
	b.WriteString(`<html data-theme="` + html.EscapeString(theme) + `"`)
	if variant != "" {
		b.WriteString(` data-variant="` + html.EscapeString(variant) + `"`)
	}
	if motion == "reduced" {
		b.WriteString(` data-motion="reduced"`)
	}
	if contrast == "high" {
		b.WriteString(` data-contrast="high"`)
	}
	// One style attribute carries both inline overrides: density, and the
	// theme tint token (inline beats the theme's root block and variants).
	var style []string
	if density != "1" {
		style = append(style, "--density:"+density)
	}
	if spec := themeTintSpec(theme); spec != nil && normalizeTint(tint) != "" {
		style = append(style, spec.Token+":"+normalizeTint(tint))
	}
	if len(style) > 0 {
		b.WriteString(` style="` + html.EscapeString(strings.Join(style, ";")) + `"`)
	}
	b.WriteString(">")
	return template.HTML(b.String())
}

// themeManifest mirrors ftl-themes' dist/themes.json entries. Version is
// the build's content hash (identical across every entry) - used to
// cache-bust theme asset URLs; scheme/luminance/shellAware are picker
// metadata per CONTRACT.md.
type themeManifest struct {
	Slug        string   `json:"slug"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	Scheme      string   `json:"scheme"`
	Luminance   *float64 `json:"luminance"`
	ShellAware  bool     `json:"shellAware"`
	// Variants are the theme's palette variants (sub-themes), offered in
	// the picker beneath the theme. Absent on most themes.
	Variants []themeVariantEntry `json:"variants"`
	// Tint is the theme's user-chosen colour, if it declares one: the app
	// must offer it next to the theme choice (CONTRACT.md "Theme tint").
	Tint *themeTintEntry `json:"tint"`
}

type themeTintEntry struct {
	Token   string `json:"token"`
	Default string `json:"default"`
	Label   string `json:"label"`
}

type themeVariantEntry struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// themeAssetPath maps a path inside the submodule to its embed path.
func themeAssetPath(rel string) string { return "third_party/ftl-themes/" + rel }

var (
	themeListOnce sync.Once
	themeList     []themeManifest
	themeVersionV string // build version from the manifest, for cache-busting
)

// availableThemes reads the embedded manifest once: only ftl-themes
// bundles, no synthesized entries - the dashboard always links one theme.
func availableThemes() []themeManifest {
	themeListOnce.Do(func() {
		themeList = nil
		data, err := embeddedThemes.ReadFile(themeAssetPath("dist/themes.json"))
		if err != nil {
			logWarnf("theme manifest unreadable: %v", err)
			return
		}
		var parsed []themeManifest
		if err := json.Unmarshal(data, &parsed); err != nil {
			logWarnf("theme manifest unparseable: %v", err)
			return
		}
		if len(parsed) > 0 {
			themeVersionV = parsed[0].Version
		}
		themeList = append(themeList, parsed...)
	})
	return themeList
}

// themeBuildVersion returns the manifest's build version ("" when the
// manifest was unreadable), for cache-busting theme asset URLs.
func themeBuildVersion() string {
	availableThemes()
	return themeVersionV
}

// themeCSSHref returns the versioned URL for a theme bundle. Version query
// per CONTRACT.md "Cache-busting": a stale cached bundle after an upgrade
// would otherwise 404 its own assets or show old colors.
func themeCSSHref(slug string) string {
	return "/static/themes/" + slug + ".css?v=" + themeBuildVersion()
}

// iconSpriteHref returns the per-theme icon sprite URL.
func iconSpriteHref(slug string) string {
	return "/static/themes/icons/" + slug + ".svg"
}

// isKnownTheme reports whether a slug names a bundle that is actually
// embedded. Guards the static route and any persisted value.
func isKnownTheme(slug string) bool {
	if slug == "" {
		return false
	}
	for _, t := range availableThemes() {
		if t.Slug == slug {
			return true
		}
	}
	return false
}

// themeHasVariant reports whether slug's manifest entry lists variant id.
// "" (the theme's own palette) is not a variant.
func themeHasVariant(slug, id string) bool {
	if id == "" {
		return false
	}
	for _, t := range availableThemes() {
		if t.Slug == slug {
			for _, v := range t.Variants {
				if v.ID == id {
					return true
				}
			}
		}
	}
	return false
}

// currentThemeVariant returns the active palette variant of the active
// theme, "" when none is chosen or it does not belong to that theme.
func currentThemeVariant() string {
	theme := currentTheme()
	mutex.Lock()
	v := themeVariant
	mutex.Unlock()
	if !themeHasVariant(theme, v) {
		return ""
	}
	return v
}

// currentTheme returns the active slug, falling back to the default when
// the persisted value names a bundle that no longer ships (e.g. an
// upstream-archived theme or an old "none"). Caller holds no lock.
func currentTheme() string {
	mutex.Lock()
	defer mutex.Unlock()
	if !isKnownTheme(themeSlug) {
		return defaultThemeSlug
	}
	return themeSlug
}

// themeChoice is one entry of the theme picker: a theme with its own
// palette (Variant "") or one of its palette variants. The picker posts the
// choice's index in themeChoices().
type themeChoice struct {
	Slug, Variant, Label string
}

// themeChoices lists every theme in manifest order, each followed by its
// variants, so a variant always sits beneath its theme (CONTRACT.md).
func themeChoices() []themeChoice {
	var out []themeChoice
	for _, t := range availableThemes() {
		out = append(out, themeChoice{Slug: t.Slug, Label: t.Label})
		for _, v := range t.Variants {
			out = append(out, themeChoice{Slug: t.Slug, Variant: v.ID, Label: v.Label})
		}
	}
	return out
}

// themeChoiceIndex returns the picker index of (slug, variant), -1 if none.
func themeChoiceIndex(slug, variant string) int {
	for i, c := range themeChoices() {
		if c.Slug == slug && c.Variant == variant {
			return i
		}
	}
	return -1
}

// themePickerView groups the choices for the picker template: a theme
// without variants is a plain option, a theme with variants an <optgroup>
// holding its own palette first and then each variant.
type themePickerView struct {
	Groups []themePickerGroup
}

type themePickerGroup struct {
	Label   string // optgroup label; "" for a theme without variants
	Options []themePickerOption
}

type themePickerOption struct {
	Idx      int
	Label    string
	Selected bool
}

func themePicker() themePickerView {
	active := themeChoiceIndex(currentTheme(), currentThemeVariant())
	var v themePickerView
	i := 0
	for _, t := range availableThemes() {
		g := themePickerGroup{}
		if len(t.Variants) > 0 {
			g.Label = t.Label
		}
		g.Options = append(g.Options, themePickerOption{Idx: i, Label: t.Label, Selected: i == active})
		i++
		for _, tv := range t.Variants {
			g.Options = append(g.Options, themePickerOption{Idx: i, Label: tv.Label, Selected: i == active})
			i++
		}
		v.Groups = append(v.Groups, g)
	}
	return v
}

var themeFragmentTmpl = template.Must(template.New("theme-select").Parse(`<div id="theme" class="setting-cell">
<div class="field-row">
<form hx-post="/api/settings/theme" hx-target="#theme" hx-swap="outerHTML">
<label class="label">Theme</label>
<select name="idx" class="select" onchange="this.form.requestSubmit()">
{{range .Groups}}{{if .Label}}<optgroup label="{{.Label}}">{{end}}{{range .Options}}<option value="{{.Idx}}" {{if .Selected}}selected{{end}}>{{.Label}}</option>{{end}}{{if .Label}}</optgroup>{{end}}
{{end}}</select>
</form>
</div>
</div>`))

// The three library display options (CONTRACT.md "User display options"):
// density/motion/contrast ride the documentElement, not the theme, so a
// look stays intact while accessibility needs are met. Select fragments
// post here; the response re-renders the row and OOB-updates the carrier
// attributes so no reload is needed (the live sockets survive). Default
// values REMOVE the carrier, matching an untouched page.
type displayOption struct {
	id      string
	post    string
	label   string
	options []string
	// get returns the current selection index; set applies one.
	get func() int
	set func(int)
	// carrier renders the documentElement update for the applied value.
	carrier func(int) string
}

var displayOptions = []displayOption{
	{
		id: "motion", post: "/api/settings/motion", label: "Motion",
		options: []string{"Full", "Reduced"},
		get:     func() int { return boolIdx(displayMotion == "reduced") },
		set:     func(i int) { displayMotion = map[int]string{0: "full", 1: "reduced"}[i] },
		carrier: func(i int) string {
			if i == 1 {
				return `document.documentElement.setAttribute("data-motion","reduced")`
			}
			return `document.documentElement.removeAttribute("data-motion")`
		},
	},
	{
		id: "contrast", post: "/api/settings/contrast", label: "Contrast",
		options: []string{"Standard", "High"},
		get:     func() int { return boolIdx(displayContrast == "high") },
		set:     func(i int) { displayContrast = map[int]string{0: "standard", 1: "high"}[i] },
		carrier: func(i int) string {
			if i == 1 {
				return `document.documentElement.setAttribute("data-contrast","high")`
			}
			return `document.documentElement.removeAttribute("data-contrast")`
		},
	},
	{
		id: "density", post: "/api/settings/density", label: "Density",
		options: []string{"Normal", "Compact", "Comfortable"},
		get:     func() int { return displayDensityIdx },
		set: func(i int) {
			if i < len(displayDensityValues) {
				displayDensityIdx = i
			}
		},
		carrier: func(i int) string {
			if d := displayDensityValues[i]; d != "1" {
				return `document.documentElement.style.setProperty("--density","` + d + `")`
			}
			return `document.documentElement.style.removeProperty("--density")`
		},
	},
}

func boolIdx(b bool) int {
	if b {
		return 1
	}
	return 0
}

// view is the option's select row at its current value.
func (opt displayOption) view() selectView {
	return settingSelect(opt.id, opt.post, opt.label, "", func() optionsView { return optionsView{Options: opt.options, Idx: opt.get()} })
}

func registerDisplayOptionRoutes(mux *http.ServeMux) {
	for _, opt := range displayOptions {
		opt := opt
		mux.HandleFunc("POST "+opt.post, requireAuth(func(w http.ResponseWriter, r *http.Request) {
			idx, err := strconv.Atoi(r.FormValue("idx"))
			if err != nil || idx < 0 || idx >= len(opt.options) {
				http.Error(w, "bad idx", http.StatusBadRequest)
				return
			}
			mutex.Lock()
			opt.set(idx)
			settingChanged()
			mutex.Unlock()
			noteActivity()
			renderFragment(w, selectFragmentTmpl, opt.view())
			// Carrier update rides out-of-band so the applied value takes
			// effect immediately (same pattern as the theme swap).
			fmt.Fprintf(w, "\n<script hx-swap-oob=\"true\">%s</script>", opt.carrier(idx))
		}))
	}
}

// handleAPISettingsTheme persists the chosen theme and tells the page to
// swap its stylesheet. The theme lives in the unit's config beside every
// other setting, so it follows the device rather than the browser - the
// front panel and the web UI share one state, as they do for brightness.
func handleAPISettingsTheme(w http.ResponseWriter, r *http.Request) {
	themeChanged, variantChanged := false, false
	if idx, err := strconv.Atoi(r.FormValue("idx")); err == nil {
		all := themeChoices()
		if idx >= 0 && idx < len(all) {
			c := all[idx]
			mutex.Lock()
			themeChanged = themeSlug != c.Slug
			variantChanged = themeChanged || themeVariant != c.Variant
			themeSlug, themeVariant = c.Slug, c.Variant
			// A preset is a sub-theme: choosing one clears the theme's custom
			// tint so the preset shows (CONTRACT.md "Theme tint" step 3).
			if c.Variant != "" && themeTints[c.Slug] != "" {
				delete(themeTints, c.Slug)
				variantChanged = true
			}
			if variantChanged {
				settingChanged()
			}
			mutex.Unlock()
		}
	}
	renderFragment(w, themeFragmentTmpl, themePicker())
	if variantChanged {
		// The tint control follows the theme (shown only when it declares a
		// tint) and the inline tint token follows the stored colour.
		tv := currentTintView()
		tv.OOB = true
		w.Write([]byte("\n"))
		renderFragment(w, tintFragmentTmpl, tv)
	}
	if variantChanged && !themeChanged {
		// Same bundle, other palette: only the marker attribute changes.
		fmt.Fprintf(w, "\n<script hx-swap-oob=\"true\">%s;%stelePalette=null</script>", variantCarrier(currentThemeVariant()), tintCarrier())
	}
	if themeChanged {
		// Out-of-band swap of the <link> and the <html data-theme> marker so
		// the change is visible immediately, without a reload that would lose
		// the live meter and telemetry sockets.
		active := currentTheme()
		href := fmt.Sprintf(" href=%q", themeCSSHref(active))
		fmt.Fprintf(w, "\n<link id=\"themecss\" rel=\"stylesheet\"%s hx-swap-oob=\"outerHTML\">", href)
		// Charts snapshot the palette at creation (see telePaletteInit), so
		// drop them: the next telemetry push (<=2s) rebuilds them in the new
		// theme's colors instead of keeping stale ones until a reload.
		// hx-swap-oob="true" marks this as out-of-band content to execute
		// in place: a bare <script> after the OOB <link> relied on htmx
		// executing in-swapped scripts, which multi-node responses don't
		// guarantee. The sprite rewrite keeps every .icon <use> pointed
		// at the new theme's icon set (same ids, theme-authored shapes).
		fmt.Fprintf(w, "\n<script hx-swap-oob=\"true\">document.documentElement.setAttribute(\"data-theme\",%q);%s;%sSPRITE=%q;teleCPU=teleRAM=teleTemp=teleDisk=teleSub=telePalette=null;document.querySelectorAll('.icon use').forEach(function(u){u.setAttribute('href',SPRITE)})</script>", active, variantCarrier(currentThemeVariant()), tintCarrier(), iconSpriteHref(active))
	}
}

// tintView is the theme tint setting cell (CONTRACT.md "Theme tint"):
// shown only for a theme that declares a tint, as a plain colour input
// posted like every other setting. OOB marks it as an out-of-band swap
// riding a theme-picker response.
type tintView struct {
	Show   bool
	OOB    bool
	Token  string
	Label  string
	Value  string // colour shown: the stored one, else the theme default
	Custom bool   // a custom colour is stored (Default resets it)
}

func currentTintView() tintView {
	theme := currentTheme()
	spec := themeTintSpec(theme)
	if spec == nil {
		return tintView{}
	}
	v := tintView{Show: true, Token: spec.Token, Label: spec.Label, Value: normalizeTint(spec.Default)}
	if v.Label == "" {
		v.Label = "Theme tint"
	}
	if c := currentThemeTint(theme); c != "" {
		v.Value, v.Custom = c, true
	}
	return v
}

// With no custom colour the input shows what is in effect (a preset's
// colour, read from the stylesheet once it has loaded), like the library's
// own control. Dragging previews live; release saves.
var tintFragmentTmpl = template.Must(template.New("tint").Parse(`{{if .Show}}<div id="tint" class="setting-cell"{{if .OOB}} hx-swap-oob="outerHTML"{{end}}>
<div class="field-row">
<form hx-post="/api/settings/tint" hx-target="#tint" hx-swap="outerHTML">
<label class="label" for="tintcolor">{{.Label}}</label>
<input id="tintcolor" class="tint-picker" type="color" name="tint" value="{{.Value}}" style="inline-size:2.4rem;block-size:2rem;padding:0;cursor:pointer" oninput="document.documentElement.style.setProperty({{.Token}},this.value)" onchange="this.form.requestSubmit()">
{{if .Custom}}<button class="btn btn-secondary btn-sm" type="submit" name="reset" value="1">Default</button>{{else}}<script>(function(){var i=document.getElementById("tintcolor"),v=getComputedStyle(document.documentElement).getPropertyValue({{.Token}}).trim();if(/^#[0-9a-f]{6}$/i.test(v))i.value=v})()</script>{{end}}
</form>
</div>
</div>{{else}}<div id="tint" hidden{{if .OOB}} hx-swap-oob="outerHTML"{{end}}></div>{{end}}`))

// tintCarrier is the documentElement update that applies the active
// theme's tint: drop every tint token, then set the stored colour, if any.
func tintCarrier() string {
	var b strings.Builder
	for _, tok := range tintTokens() {
		fmt.Fprintf(&b, "document.documentElement.style.removeProperty(%q);", tok)
	}
	theme := currentTheme()
	if spec := themeTintSpec(theme); spec != nil {
		if c := currentThemeTint(theme); c != "" {
			fmt.Fprintf(&b, "document.documentElement.style.setProperty(%q,%q);", spec.Token, c)
		}
		// Show the colour now in effect (the custom one, or the preset's),
		// read once the variant above has applied.
		// The tint cell swapped in by the same response settles after this
		// runs (htmx settle delay), and after a theme change the new bundle
		// loads asynchronously: sync again after the settle and on load.
		fmt.Fprintf(&b, `(function(){function s(){var i=document.getElementById("tintcolor"),v=getComputedStyle(document.documentElement).getPropertyValue(%q).trim();if(i&&/^#[0-9a-f]{6}$/i.test(v))i.value=v}s();setTimeout(s,100);var l=document.getElementById("themecss");if(l)l.addEventListener("load",s,{once:true})})();`, spec.Token)
	}
	return b.String()
}

// handleAPISettingsTint stores (or with reset=1 clears) the active theme's
// tint colour. Only a theme that declares a tint accepts one, and only as
// #rrggbb: the colour lands in an inline style on every page.
func handleAPISettingsTint(w http.ResponseWriter, r *http.Request) {
	theme := currentTheme()
	if themeTintSpec(theme) == nil {
		http.Error(w, "this theme has no tint", http.StatusBadRequest)
		return
	}
	colour := ""
	if r.FormValue("reset") == "" {
		if colour = normalizeTint(r.FormValue("tint")); colour == "" {
			http.Error(w, "tint must be #rrggbb", http.StatusBadRequest)
			return
		}
	}
	mutex.Lock()
	if themeTints[theme] != colour {
		if colour == "" {
			delete(themeTints, theme)
		} else {
			themeTints[theme] = colour
		}
		settingChanged()
	}
	mutex.Unlock()
	noteActivity()
	renderFragment(w, tintFragmentTmpl, currentTintView())
	fmt.Fprintf(w, "\n<script hx-swap-oob=\"true\">%stelePalette=null</script>", tintCarrier())
}

// variantCarrier is the documentElement update for a palette variant: set
// data-variant, or remove it for the theme's own palette.
func variantCarrier(variant string) string {
	if variant == "" {
		return `document.documentElement.removeAttribute("data-variant")`
	}
	return fmt.Sprintf(`document.documentElement.setAttribute("data-variant",%q)`, variant)
}

type dashboardData struct {
	DeviceName           string
	Logo                 template.HTML
	Theme                string
	ThemeCSS             string
	CoreVersion          string
	IconSprite           string
	HTMLTag              template.HTML
	ThemeFragment        template.HTML
	TintFragment         template.HTML
	MotionFragment       template.HTML
	ContrastFragment     template.HTML
	DensityFragment      template.HTML
	VURangeFragment      template.HTML
	PeakHoldFragment     template.HTML
	SampleRateFragment   template.HTML
	ChannelCountFragment template.HTML
	TagFragment          template.HTML
	PrefixFragment       template.HTML
	TransportFragment    template.HTML
	HyperdeckFragment    template.HTML
	TimecodeFragment     template.HTML
	RxLatencyFragment    template.HTML
	LogLevelFragment     template.HTML
	BrightnessFragment   template.HTML
	AutoDimFragment      template.HTML
	MonitorFragment      template.HTML
	DemoFragment         template.HTML
	DeviceNameFragment   template.HTML
	WifiEnabled          bool
	WifiSSID             string
	WifiPassword         string
	WifiQRFragment       template.HTML
	TransportIcon        bool
}

// optionsView is the shared shape behind the settings-dropdown option lists
// - both the initial dashboard render and each setting's htmx POST handler
// read the same options through this, so there's exactly one place that
// builds each list (see the selectView descriptors below).
type optionsView struct {
	Options []string
	Idx     int
}

// selectView carries one settings-dropdown fragment. The six select-based
// settings (meter range, peak hold, sample rate, tag, transport mode, log
// level) render identical markup, differing only in anchor id, endpoint,
// label, option labels, and selected index - so one template serves them all.
// Suffix is appended verbatim to every option label (vuRange's "dBFS").
type selectView struct {
	Id      string
	Post    string
	Label   string
	Suffix  string
	Options []string
	Idx     int
}

func settingSelect(id, post, label, suffix string, opts func() optionsView) selectView {
	v := opts()
	return selectView{Id: id, Post: post, Label: label, Suffix: suffix, Options: v.Options, Idx: v.Idx}
}

func vuRangeSelect() selectView {
	return settingSelect("vurange", "/api/settings/vu-range", "Meter Range", "dBFS", vuRangeOptionsView)
}

func peakHoldSelect() selectView {
	return settingSelect("peakhold", "/api/settings/peak-hold", "Peak Hold", "", peakHoldOptionsView)
}

func sampleRateSelect() selectView {
	return settingSelect("samplerate", "/api/settings/sample-rate", "Sample Rate", "", sampleRateOptionsView)
}

func tagSelect() selectView {
	return settingSelect("tag", "/api/settings/tag", "Tag", "", tagOptionsView)
}

func logLevelSelect() selectView {
	return settingSelect("loglevel", "/api/settings/log-level", "Log Level", "", logLevelOptionsView)
}

var selectFragmentTmpl = template.Must(template.New("setting-select").Parse(`<div id="{{.Id}}" class="setting-cell">
<div class="field-row">
<form hx-post="{{.Post}}" hx-target="#{{.Id}}" hx-swap="outerHTML">
<label class="label">{{.Label}}</label>
<select name="idx" class="select" onchange="this.form.requestSubmit()">
{{range $i, $v := .Options}}<option value="{{$i}}" {{if eq $i $.Idx}}selected{{end}}>{{$v}}{{$.Suffix}}</option>{{end}}
</select>
</form>
</div>
</div>`))

func vuRangeOptionsView() optionsView {
	mutex.Lock()
	defer mutex.Unlock()
	opts := make([]string, len(vuRangeOptions))
	for i, v := range vuRangeOptions {
		opts[i] = fmt.Sprintf("%d", int(v))
	}
	return optionsView{Options: opts, Idx: vuRangeIdx}
}

func peakHoldOptionsView() optionsView {
	mutex.Lock()
	defer mutex.Unlock()
	opts := make([]string, len(peakHoldOptions))
	for i, d := range peakHoldOptions {
		if d == 0 {
			opts[i] = "Off"
		} else {
			opts[i] = d.String()
		}
	}
	return optionsView{Options: opts, Idx: peakHoldIdx}
}

func sampleRateOptionsView() optionsView {
	mutex.Lock()
	defer mutex.Unlock()
	opts := make([]string, len(sampleRates))
	for i, r := range sampleRates {
		opts[i] = fmt.Sprintf("%dkHz", r/1000)
	}
	return optionsView{Options: opts, Idx: sampleRateIdx}
}

// currentChannelCountView carries the data the channel-count setting needs:
// a direct numeric input (1..MaxChannelCount) rather than a dropdown, since
// the legal range is wide and every value is valid.
type channelCountView struct {
	Count int
	Max   int
}

func currentChannelCountView() channelCountView {
	mutex.Lock()
	defer mutex.Unlock()
	return channelCountView{Count: channelCount, Max: MaxChannelCount}
}

func tagOptionsView() optionsView {
	mutex.Lock()
	defer mutex.Unlock()
	opts := make([]string, len(tagPresets))
	for i, t := range tagPresets {
		if t == "" {
			opts[i] = "None"
		} else {
			opts[i] = t
		}
	}
	return optionsView{Options: opts, Idx: tagPresetIdx}
}

// brightnessFragmentTmpl is the Display -> Brightness setting: a 0-100
// slider (the OLED's continuous brightness control) that live-updates its
// readout while dragging and submits on release, so the panel responds only
// when the operator finishes moving it.
var brightnessFragmentTmpl = template.Must(template.New("brightness").Parse(`<div id="brightness" class="setting-cell">
<div class="field-row">
<form hx-post="/api/settings/brightness" hx-target="#brightness" hx-swap="outerHTML">
<label class="label" for="brightnessRange">Brightness</label>
<span class="hint field-hint" id="brightnessVal">{{.Pct}}%</span>
<input id="brightnessRange" class="slider" type="range" name="pct" min="0" max="100" step="1" value="{{.Pct}}" oninput="document.getElementById('brightnessVal').textContent=this.value+'%'" onchange="this.form.requestSubmit()" title="Panel brightness 0-100%">
</form>
</div>
</div>`))

// switchFragmentTmpl renders every on/off setting (Auto Dim, HyperDeck
// Control, Demo Mode, Monitoring) as the same switch markup; Readout labels
// the two states and Hint, when set, adds a caveat row under the switch.
var switchFragmentTmpl = template.Must(template.New("switch").Parse(`<div id="{{.Id}}" class="setting-cell">
<div class="field-row">
<form hx-post="{{.Post}}" hx-target="#{{.Id}}" hx-swap="outerHTML">
<label class="label" for="{{.InputId}}">{{.Label}}</label>
<label class="switch" for="{{.InputId}}">
<input id="{{.InputId}}" name="enabled" type="checkbox" {{if .Enabled}}checked{{end}} onchange="this.form.requestSubmit()">
<span class="switch-track"><span class="switch-thumb"></span></span>
<span class="switch-readout" {{.Readout}}></span>
</label>
</form>
</div>
{{if .Hint}}<div class="field-row"><span class="hint field-hint">{{.Hint}}</span></div>
{{end}}</div>`))

// switchView is one on/off setting row; the *Switch functions build it
// from the live flag under the app mutex.
type switchView struct {
	Id, Post, InputId, Label, Hint string
	// Readout is the data-on/data-off pair. Passed whole: html/template
	// reads a templated "data-on" value as an on* event handler and would
	// JS-quote it.
	Readout template.HTMLAttr
	Enabled bool
}

func readout(on, off string) template.HTMLAttr {
	return template.HTMLAttr(`data-on="` + on + `" data-off="` + off + `"`)
}

func autoDimSwitch() switchView {
	mutex.Lock()
	defer mutex.Unlock()
	return switchView{Id: "autodim", Post: "/api/settings/dim", InputId: "autoDimToggle", Label: "Auto Dim", Readout: readout("AUTO", "MANUAL"), Enabled: autoDimEnabled}
}

// hyperdeckSwitch is Transport -> HyperDeck Control (TCP 9993); the hint
// states the no-auth caveat so the toggle reads as an informed choice.
func hyperdeckSwitch() switchView {
	mutex.Lock()
	defer mutex.Unlock()
	return switchView{Id: "hyperdeck", Post: "/api/settings/hyperdeck", InputId: "hyperdeckToggle", Label: "HyperDeck Control", Readout: readout("ON", "OFF"),
		Hint: "TCP 9993, Blackmagic protocol, no auth while on", Enabled: hyperdeckEnabled}
}

func demoSwitch() switchView {
	mutex.Lock()
	defer mutex.Unlock()
	return switchView{Id: "demo", Post: "/api/settings/demo", InputId: "demoToggle", Label: "Demo Mode", Readout: readout("DEMO", "LIVE"), Enabled: demoMode}
}

func monitorSwitch() switchView {
	mutex.Lock()
	defer mutex.Unlock()
	return switchView{Id: "monitor", Post: "/api/settings/monitor", InputId: "monitorToggle", Label: "Monitoring", Readout: readout("ON", "OFF"), Enabled: monitoring}
}

// brightnessView carries the exact value the fragment renders, so both the
// dashboard and the htmx POST handler share one template.
type brightnessView struct {
	Pct int
}

func brightnessViewData() brightnessView {
	mutex.Lock()
	defer mutex.Unlock()
	return brightnessView{Pct: oledBrightnessPct}
}

func handleAPISettingsBrightness(w http.ResponseWriter, r *http.Request) {
	if pct, err := strconv.Atoi(r.FormValue("pct")); err == nil {
		mutex.Lock()
		if pct >= 0 && pct <= 100 {
			oledBrightnessPct = pct
			noteActivity() // a WebUI brightness change is input - wake the panel
			if hwManager != nil {
				hwManager.SetBrightness(oledBrightnessPct)
			}
			settingChanged()
		}
		mutex.Unlock()
	}
	renderFragment(w, brightnessFragmentTmpl, brightnessViewData())
}

func handleAPISettingsAutoDim(w http.ResponseWriter, r *http.Request) {
	enabled := r.FormValue("enabled") != ""
	mutex.Lock()
	autoDimEnabled = enabled
	// Either way this is an input while the panel may be dimmed/off: wake it
	// (turning dim off restores the screen, turning it on restarts the idle
	// clock from full brightness).
	noteActivity()
	settingChanged()
	mutex.Unlock()
	renderFragment(w, switchFragmentTmpl, autoDimSwitch())
}

func handleAPISettingsHyperdeck(w http.ResponseWriter, r *http.Request) {
	enabled := r.FormValue("enabled") != ""
	mutex.Lock()
	setHyperdeckEnabledLocked(enabled)
	settingChanged()
	noteActivity()
	mutex.Unlock()
	renderFragment(w, switchFragmentTmpl, hyperdeckSwitch())
}

func handleAPISettingsDemoMode(w http.ResponseWriter, r *http.Request) {
	enabled := r.FormValue("enabled") != ""
	mutex.Lock()
	ok := setDemoModeLocked(enabled)
	noteActivity()
	mutex.Unlock()
	if !ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `<span class="err">BUSY - STOP FIRST</span>`)
		return
	}
	renderFragment(w, switchFragmentTmpl, demoSwitch())
}

func handleAPISettingsMonitor(w http.ResponseWriter, r *http.Request) {
	enabled := r.FormValue("enabled") != ""
	var done chan struct{}
	mutex.Lock()
	if enabled {
		startMonitor()
		// startMonitor no-ops when Inferno is down/recording: only claim
		// an auto session that actually exists (see doStartInferno).
		if monitoring {
			autoMonitor = true
		}
	} else {
		autoMonitor = false
		done = monitorDone
		stopMonitor()
	}
	noteActivity()
	mutex.Unlock()
	// stopMonitor only signals; the reaper clears the flag. Wait for it
	// (mutex-free) so the re-rendered switch reflects the real state.
	if done != nil {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
	renderFragment(w, switchFragmentTmpl, monitorSwitch())
}

var channelCountFragmentTmpl = template.Must(template.New("channelcount").Parse(`<div id="channelcount" class="setting-cell">
<div class="field-row">
<form hx-post="/api/settings/channels" hx-swap="none" hx-sync="this:queue last" hx-status:400="target:#channels-error swap:innerHTML">
<label class="label" for="channelsInput">Channels</label>
<input id="channelsInput" class="input" type="number" name="count" min="1" max="{{.Max}}" step="1" value="{{.Count}}" onchange="this.form.requestSubmit()" oninput="document.getElementById('channels-error').textContent=''" title="Number of input channels">
<span class="hint field-hint">1–{{.Max}}</span>
</form>
</div>
<div id="channels-error"></div>
</div>`))

// prefixView carries the current filename prefix for the free-text Prefix
// field. A blank value renders an empty box with the default as placeholder;
// submitting clears a custom prefix back to the default.
type prefixView struct {
	Prefix string
}

// filePrefixFragmentTmpl is the WebUI free-text Prefix field (the OLED gets
// the preset-list picker instead, per the Round 3 design decision: WebUI
// text field + OLED presets). It posts the literal prefix, validated to a
// filename-safe charset server-side.
var filePrefixFragmentTmpl = template.Must(template.New("fileprefix").Parse(`<div id="fileprefix" class="setting-cell">
<div class="field-row">
<form hx-post="/api/settings/prefix" hx-target="#fileprefix" hx-swap="outerHTML" hx-status:400="target:#prefix-error">
<label class="label" for="filePrefixInput">Prefix</label>
<div class="input-group">
<input id="filePrefixInput" class="input" name="prefix" type="text" value="{{.Prefix}}" maxlength="32" placeholder="recording" pattern="[A-Za-z0-9 \-]+" title="Letters, numbers, spaces and - only (no underscores)">
<button type="submit" class="btn btn-secondary">Save</button>
</div>
<span class="hint field-hint">file_YYYYMMDD…</span>
</form>
<div id="prefix-error"></div>
</div>
</div>`))

func filePrefixView() prefixView {
	mutex.Lock()
	defer mutex.Unlock()
	return prefixView{Prefix: filePrefix}
}

func handleAPISettingsPrefix(w http.ResponseWriter, r *http.Request) {
	prefix := strings.TrimSpace(r.FormValue("prefix"))
	if prefix == "" || isValidFilePrefix(prefix) {
		mutex.Lock()
		filePrefix = prefix
		settingChanged()
		mutex.Unlock()
		logInfof("recording prefix set to %q via remote", effectiveFilePrefix())
	} else {
		logWarnf("rejected invalid recording prefix %q via remote", prefix)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `<span class="err">Letters, numbers, spaces and - only (max 32)</span>`)
		return
	}
	renderFragment(w, filePrefixFragmentTmpl, filePrefixView())
	// OOB swap: clear any stale validation error from #prefix-error on success.
	fmt.Fprint(w, "\n<div id=\"prefix-error\" hx-swap-oob=\"innerHTML\"></div>")
}

// transportSelect switches the main transport buttons between icon
// SVG glyphs and text labels (see the ICON/TEXT setting).
func transportSelect() selectView {
	return settingSelect("transportmode", "/api/settings/transport-mode", "Transport Buttons", "", transportOptionsView)
}

var transportModes = []string{"icon", "text"}

func transportOptionsView() optionsView {
	idx := 0
	if transportMode == "text" {
		idx = 1
	}
	return optionsView{Options: []string{"Icon", "Text"}, Idx: idx}
}

func handleAPISettingsTransportMode(w http.ResponseWriter, r *http.Request) {
	handleSelectSetting(w, r, len(transportModes), func(i int) { transportMode = transportModes[i]; settingChanged() }, transportSelect)
}

// wifiQRView carries the data needed to render the WiFi join QR code in the
// dashboard settings modal. The QR is generated via skip2/go-qrcode into a
// base64 PNG so it can be embedded directly in the HTML without extra
// endpoints.
type wifiQRView struct {
	Enabled  bool
	SSID     string
	QRBase64 string
}

// wifiQRFragment renders the join-QR row; the code is drawn only while the
// AP is on with an SSID set.
func wifiQRFragment(enabled bool, ssid, pass string) template.HTML {
	v := wifiQRView{Enabled: enabled, SSID: ssid}
	if enabled && ssid != "" {
		if code, err := qrcode.New(wifiQRContent(ssid, pass), qrcode.Medium); err == nil {
			png, _ := code.PNG(256)
			v.QRBase64 = base64.StdEncoding.EncodeToString(png)
		}
	}
	return frag(wifiQRFragmentTmpl, v)
}

var wifiQRFragmentTmpl = template.Must(template.New("wifiqr").Parse(`
<div id="wifiqr">
{{if .Enabled}}
<div class="wifi-qr-row">
  <div class="wifi-qr-info">
    <p><strong>SSID:</strong> {{.SSID}}</p>
  </div>
  <div class="wifi-qr-img">
    <img src="data:image/png;base64,{{.QRBase64}}" alt="WiFi QR Code" title="Scan to join">
  </div>
</div>
{{else}}
<p class="dim">WiFi AP is off. Enable it below to start broadcasting.</p>
{{end}}
</div>
`))

// handleSelectSetting applies a dropdown's posted index when it is in
// [0, n) - apply runs under the app mutex - and re-renders the row either
// way, so a bad value just shows the unchanged setting.
func handleSelectSetting(w http.ResponseWriter, r *http.Request, n int, apply func(int), view func() selectView) {
	if idx, err := strconv.Atoi(r.FormValue("idx")); err == nil && idx >= 0 && idx < n {
		mutex.Lock()
		apply(idx)
		mutex.Unlock()
	}
	renderFragment(w, selectFragmentTmpl, view())
}

func handleAPISettingsVURange(w http.ResponseWriter, r *http.Request) {
	handleSelectSetting(w, r, len(vuRangeOptions), func(i int) { vuRangeIdx = i; settingChanged() }, vuRangeSelect)
}

func logLevelOptionsView() optionsView {
	return optionsView{Options: logLevelNames, Idx: int(currentLogLevel())}
}

func handleAPISettingsLogLevel(w http.ResponseWriter, r *http.Request) {
	handleSelectSetting(w, r, len(logLevelNames), func(i int) { setLogLevel(LogLevel(i)) }, logLevelSelect)
}

func handleAPISettingsPeakHold(w http.ResponseWriter, r *http.Request) {
	handleSelectSetting(w, r, len(peakHoldOptions), func(i int) { peakHoldIdx = i; settingChanged() }, peakHoldSelect)
}

func handleAPISettingsSampleRate(w http.ResponseWriter, r *http.Request) {
	handleSelectSetting(w, r, len(sampleRates), func(i int) {
		sampleRateIdx = i
		checkInfernoRestart()
		settingChanged()
	}, sampleRateSelect)
}

// handleAPISettingsChannels applies a channel count. The number box is not
// swapped on success (204): replacing an input the operator is still
// spinning overwrote the newer value they had already entered with the
// server's echo of an older one. A refused value answers 400 with a
// message, so the field never silently disagrees with the unit.
func handleAPISettingsChannels(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.FormValue("count"))
	if err != nil || n < 1 || n > MaxChannelCount {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `<span class="err">Channels must be 1-%d</span>`, MaxChannelCount)
		return
	}
	mutex.Lock()
	// Unchanged is a no-op: Enter in the number box fires both its change
	// handler and the form submit, and a repeat save of the same value must
	// not queue a second Inferno restart or config write.
	if n != channelCount {
		channelCount = n
		// Relaunch Inferno with the new channel count if it's running (the
		// worker's restart path re-starts monitoring too), so the running
		// instance - and with it the live VU count - always matches what
		// the settings page shows.
		checkInfernoRestart()
		settingChanged()
	}
	mutex.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func handleAPISettingsTag(w http.ResponseWriter, r *http.Request) {
	handleSelectSetting(w, r, len(tagPresets), func(i int) { tagPresetIdx = i; settingChanged() }, tagSelect)
}

// handleAPISettingsWiFi updates the WiFi access point configuration from the
// web dashboard (SSID, password, enabled toggle). Requires authentication.
func handleAPISettingsWiFi(w http.ResponseWriter, r *http.Request) {
	ssid := strings.TrimSpace(r.FormValue("ssid"))
	pass := r.FormValue("password")
	enabled := r.FormValue("enabled") == "on"

	mutex.Lock()
	if enabled {
		// Only a save that turns the AP on needs credentials; switching it
		// off must work even when the form fields were cleared.
		if msg := validateWifiCredentials(ssid, pass); msg != "" {
			mutex.Unlock()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `<span class="err">%s</span>`, html.EscapeString(msg))
			return
		}
		wifiSSID = ssid
		wifiPassword = pass
	}
	wifiEnabled = enabled
	persistConfig()
	// Capture under the about-to-release lock: the globals are reread by
	// concurrent saves/imports, so passing them after Unlock races.
	ssid, pass = wifiSSID, wifiPassword
	mutex.Unlock()

	// Re-apply the AP configuration (hostapd restart)
	go applyLatestWifiConfig()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, wifiQRFragment(enabled, ssid, pass))
	// OOB swap: clear any stale validation error from #wifi-error on success.
	fmt.Fprint(w, "\n<div id=\"wifi-error\" hx-swap-oob=\"innerHTML\"></div>")
}

// handleAPIConfigExport writes the non-secret config profile to the USB drive
// (configExportName) and reports the outcome into the settings modal's status
// line - always a 200 so htmx shows the message; the text carries failure.
func handleAPIConfigExport(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	err := exportConfig()
	mutex.Unlock()
	if err != nil {
		logErrorf("web config export: %v", err)
		fmt.Fprintf(w, "<span class=\"err\">Export failed: %s</span>", html.EscapeString(err.Error()))
		return
	}
	fmt.Fprint(w, "<span class=\"ok\">Config exported to USB drive.</span>")
}

// handleAPIConfigImport loads the USB config profile and applies it. On
// success the page is refreshed (HX-Refresh) so every settings row shows the
// imported values; on failure the message stays in the modal's status line.
func handleAPIConfigImport(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	err := importConfig()
	mutex.Unlock()
	if err != nil {
		logErrorf("web config import: %v", err)
		fmt.Fprintf(w, "<span class=\"err\">Import failed: %s</span>", html.EscapeString(err.Error()))
		return
	}
	w.Header().Set("HX-Refresh", "true")
	fmt.Fprint(w, "<span class=\"ok\">Config imported from USB - reloading...</span>")
}

// The dashboard's header ("deck") mirrors the physical front panel left to
// right - logo, OLED, rotary encoder, transport buttons - reusing the exact
// same onEncoderRotate/onEncoderClick/onButtonPress functions physical
// hardware calls, so every existing guard (recording/playback mutual
// exclusion, confirmation dialogs) applies identically. No standalone
// "hold" button: on the real unit that's a long-press of the same encoder
// button, not a separate control, so it has no web equivalent either.
// Status/config/recordings (read-only info) sit in the three-column body;
// the reel transport follows it and the level meters stay pinned to the footer.
// The page itself lives in web/dashboard.html (embedded): HTML, CSS and JS
// get editor and linter support there that a Go string literal never had.
//
//go:embed web/dashboard.html
var dashboardPage string

var dashboardTmpl = template.Must(template.New("dashboard").Parse(dashboardPage))

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	renderFragment(w, dashboardTmpl, buildDashboardData(r))
}

// handleSettingsPanes re-renders just the settings panes. The dashboard
// fetches it each time the settings sheet opens: the panes were otherwise
// rendered once at page load, so a change made on the front panel, another
// browser or a HyperDeck controller left an open dashboard showing the old
// value until a reload.
func handleSettingsPanes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardTmpl.ExecuteTemplate(w, "settingsPanes", buildDashboardData(r)); err != nil {
		logErrorf("render settingsPanes: %v", err)
	}
}

// buildDashboardData snapshots everything the dashboard template renders.
func buildDashboardData(r *http.Request) dashboardData {
	mutex.Lock()
	name := deviceName
	wifiEn := wifiEnabled
	wifiS := wifiSSID
	wifiP := wifiPassword
	transportIcon := transportMode != "text"
	mutex.Unlock()

	activeTheme := currentTheme()
	activeVariant := currentThemeVariant()
	activeThemeCSS := themeCSSHref(activeTheme)
	// ?preview=<slug> renders a theme for this browser only, without
	// persisting it: try-before-apply on shared hardware, where selecting
	// rewrites the unit's look for every browser. Unknown slugs fall back
	// to the persisted theme, never to an error page.
	if pv := r.URL.Query().Get("preview"); isKnownTheme(pv) {
		activeTheme = pv
		activeThemeCSS = themeCSSHref(pv)
		// &variant=<id> previews one of its palettes (the library's demo
		// pages use the same parameter); anything else is its own palette.
		activeVariant = ""
		if pvv := r.URL.Query().Get("variant"); themeHasVariant(pv, pvv) {
			activeVariant = pvv
		}
	}
	// The tint follows the rendered theme: its stored colour, or for a
	// preview &tint=%23rrggbb (as on the library's demo pages).
	activeTint := currentThemeTint(activeTheme)
	if pt := normalizeTint(r.URL.Query().Get("tint")); pt != "" && r.URL.Query().Get("preview") != "" {
		activeTint = pt
	}

	dispFrag := map[string]template.HTML{}
	for _, opt := range displayOptions {
		dispFrag[opt.id] = frag(selectFragmentTmpl, opt.view())
	}

	return dashboardData{
		DeviceName:           name,
		Logo:                 template.HTML(pi9696LogoSVG),
		Theme:                activeTheme,
		ThemeCSS:             activeThemeCSS,
		CoreVersion:          themeBuildVersion(),
		IconSprite:           iconSpriteHref(activeTheme),
		HTMLTag:              displayHTMLTag(activeTheme, activeVariant, activeTint),
		VURangeFragment:      frag(selectFragmentTmpl, vuRangeSelect()),
		PeakHoldFragment:     frag(selectFragmentTmpl, peakHoldSelect()),
		SampleRateFragment:   frag(selectFragmentTmpl, sampleRateSelect()),
		ChannelCountFragment: frag(channelCountFragmentTmpl, currentChannelCountView()),
		TagFragment:          frag(selectFragmentTmpl, tagSelect()),
		PrefixFragment:       frag(filePrefixFragmentTmpl, filePrefixView()),
		TransportFragment:    frag(selectFragmentTmpl, transportSelect()),
		HyperdeckFragment:    frag(switchFragmentTmpl, hyperdeckSwitch()),
		TimecodeFragment:     tcSettingsFragment(),
		RxLatencyFragment:    frag(selectFragmentTmpl, rxLatencySelect()),
		LogLevelFragment:     frag(selectFragmentTmpl, logLevelSelect()),
		ThemeFragment:        frag(themeFragmentTmpl, themePicker()),
		TintFragment:         frag(tintFragmentTmpl, currentTintView()),
		MotionFragment:       dispFrag["motion"],
		ContrastFragment:     dispFrag["contrast"],
		DensityFragment:      dispFrag["density"],
		BrightnessFragment:   frag(brightnessFragmentTmpl, brightnessViewData()),
		AutoDimFragment:      frag(switchFragmentTmpl, autoDimSwitch()),
		MonitorFragment:      frag(switchFragmentTmpl, monitorSwitch()),
		DemoFragment:         frag(switchFragmentTmpl, demoSwitch()),
		DeviceNameFragment:   frag(deviceNameFragmentTmpl, deviceNameNow()),
		WifiEnabled:          wifiEn,
		WifiSSID:             wifiS,
		WifiPassword:         wifiP,
		WifiQRFragment:       wifiQRFragment(wifiEn, wifiS, wifiP),
		TransportIcon:        transportIcon,
	}
}

// isValidDeviceName restricts the web-settable unit name to a small safe
// charset. It ends up in three places that each have their own risk if left
// unvalidated: an INFERNO_NAME env var passed to a subprocess (env values
// aren't shell-parsed, so injection isn't possible there, but a name full of
// control characters would still be a bad idea to hand to another process),
// an html/template-escaped page (safe either way, template does the
// escaping), and log lines (unescaped - control chars could forge log
// entries).
func isValidDeviceName(name string) bool {
	return isNameOf(name, "_")
}

// isNameOf reports whether s is 1-32 bytes of ASCII letters, digits,
// spaces and hyphens, plus any rune in extra.
func isNameOf(s, extra string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ' ' || c == '-' || strings.ContainsRune(extra, c)) {
			return false
		}
	}
	return true
}

// deviceNameNow reads the device name under the app mutex.
func deviceNameNow() string {
	mutex.Lock()
	defer mutex.Unlock()
	return deviceName
}

func handleAPIDeviceName(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if !isValidDeviceName(name) {
		// Same 400 pattern as prefix/WiFi: a silent 200 left the operator
		// thinking a rejected rename had saved.
		logWarnf("rejected invalid device name %q via remote", name)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `<span class="err">Letters, numbers, spaces, - and _ only (max 32)</span>`)
		return
	}
	mutex.Lock()
	deviceName = name
	persistConfig()
	mutex.Unlock()
	logInfof("Device name changed to %q via remote", name)
	// The advertised name lives on the paired device, so restart Inferno
	// (deferred while a take records or plays).
	restartInfernoServer()

	mutex.Lock()
	current := deviceName
	mutex.Unlock()
	// Wrap in the outer #devicename div: the form targets it with
	// outerHTML, and a bare <form> response would destroy the target so
	// the name is editable exactly once per page load. Markup mirrors the
	// dashboard row exactly (label/id/button), plus the error target and
	// an OOB clear of any stale validation error on success.
	renderFragment(w, deviceNameFragmentTmpl, current)
	fmt.Fprint(w, "\n<div id=\"devicename-error\" hx-swap-oob=\"innerHTML\"></div>")
}

// deviceNameFragmentTmpl is the Unit Name row, rendered by both the
// dashboard and the save response. The save used to return its own
// hand-written copy that had drifted (no label/input classes or input
// group), so the field lost its styling after every rename.
var deviceNameFragmentTmpl = template.Must(template.New("devicename").Parse(`<div id="devicename" class="setting-cell">
<div class="field-row">
<form hx-post="/api/device-name" hx-target="#devicename" hx-swap="outerHTML" hx-status:400="target:#devicename-error">
<label class="label" for="deviceNameInput">Unit Name</label>
<div class="input-group">
<input id="deviceNameInput" class="input" name="name" value="{{.}}" maxlength="32" pattern="[A-Za-z0-9 _\-]+" title="Letters, numbers, spaces, - and _ only">
<button type="submit" class="btn btn-secondary">Save</button>
</div>
</form>
</div>
<div id="devicename-error"></div>
</div>`))

// handleDisplayPNG mirrors the OLED - encoded from the supersampled canvas
// (see TTFDisplay.EncodePNG), not a separate HTML/CSS reimplementation of
// the layout that could drift from what render() actually draws. The served
// PNG can therefore show sub-nibble canvas detail the 4bpp panel quantizes
// away; noteDisplayFrame tracks both hashes so the mirror still refreshes.
//
// Encodes into an in-memory buffer under the lock, then writes to the
// response after releasing it. png.Encode writes straight through
// http.ResponseWriter to the socket - encoding directly into w while
// holding mutex would block render(), every encoder/button callback
// (physical and remote), and infernoWorker's recording guard
// for as long as a slow or stalled client's network write took, the same
// class of bug already fixed once for stopRecording().
func handleDisplayPNG(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	mutex.Lock()
	err := hwManager.EncodePNG(&buf)
	mutex.Unlock()
	if err != nil {
		logErrorf("Failed to encode display PNG: %v", err)
		http.Error(w, "failed to encode display", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	buf.WriteTo(w)
}

// The input handlers below call the exact same functions
// setupHardwareCallbacks wires to physical encoder/button interrupts - a
// remote click is indistinguishable, from the state machine's point of
// view, from a real one. That's what keeps every existing guard (recording
// blocks playback and vice versa, confirmation dialogs before delete/
// format/shutdown/restart) intact without reimplementing them here.

func handleInputEncoderRotate(direction int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		onEncoderRotate(direction)
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleInputEncoderClick(w http.ResponseWriter, r *http.Request) {
	onEncoderClick()
	w.WriteHeader(http.StatusNoContent)
}

func handleInputEncoderHold(w http.ResponseWriter, r *http.Request) {
	onEncoderHold()
	w.WriteHeader(http.StatusNoContent)
}

func handleInputButton(bt hardware.ButtonType) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		onButtonPress(bt)
		w.WriteHeader(http.StatusNoContent)
	}
}

var configTmpl = template.Must(template.New("config").Parse(`
<table>
<tr><td>Sample Rate</td><td>{{.SampleRate}}kHz</td></tr>
<tr><td>Channels</td><td>{{.Channels}}</td></tr>
<tr><td>Format</td><td>{{.Format}}</td></tr>
<tr><td>Tag</td><td>{{.Tag}}</td></tr>
<tr><td>Inferno</td><td>{{.Inferno}}</td></tr>
<tr><td>Inferno TX</td><td id="txstatus">{{.TXShort}}</td></tr>
<tr><td>Timecode</td><td id="tcstatus"></td></tr>
<tr><td>Clock</td><td>{{.Clock}}</td></tr>
<tr><td>Network</td><td>{{.Network}}</td></tr>
<tr><td>Uptime</td><td>{{.Uptime}}</td></tr>
<tr><td>Version</td><td>v{{.Version}}</td></tr>
</table>
`))

type configView struct {
	SampleRate int
	Channels   int
	Format     string
	Tag        string
	Inferno    string
	Clock      string
	Network    string
	TXShort    string // inferno TX state, kept live by the meter tick
	Uptime     string // to the minute, so the push only changes once a minute
	Version    string
}

// formatUptime renders an uptime to the minute ("3d 4h 12m", "7m"), so
// the Status table (pushed only when it changes) changes once a minute.
func formatUptime(d time.Duration) string {
	m := int(d / time.Minute)
	days, hours, mins := m/(24*60), m/60%24, m%60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

// handleAPIConfig is read-only by design: mutating settings goes through
// the encoder/button controls above (the same state machine the OLED menu
// system already guards), not a second, parallel settings form here.
func handleAPIConfig(w http.ResponseWriter, r *http.Request) {
	html, err := renderConfigHTML()
	if err != nil {
		http.Error(w, "config unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// renderConfigHTML renders the dashboard Status panel; shared by the
// one-shot GET (initial paint) and the telemetry-socket push.
func renderConfigHTML() (string, error) {
	mutex.Lock()
	v := configView{
		SampleRate: sampleRates[sampleRateIdx] / 1000,
		Channels:   channelCount,
		Format:     "WAV",
		Tag:        tagStatusText(),
		Inferno:    getInfernoStatusText(),
		Clock:      clockSyncTextLocked(time.Now()),
		Uptime:     formatUptime(time.Since(bootTime)),
		Version:    appVersion,
	}
	v.TXShort, _ = txStatusLocked()
	mutex.Unlock()

	_, v.Network = hwManager.Network.GetNetworkStatus()

	var buf bytes.Buffer
	if err := configTmpl.Execute(&buf, v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// statusTmpl is the page footer's live line (#diskInfo), pushed over the
// telemetry socket: disk space and record time left, plus a short-lived
// dashboard notice (webNotice). Owner layout (2026-10-06): the Transport
// Status state line (#status) is gone - the deck, its keys and lamps show
// the transport state, the Status table carries Inferno, uptime and TX.
var statusTmpl = template.Must(template.New("status").Parse(`Disk /rec <progress class="progress" value="{{printf "%.0f" .DiskUsed}}" max="{{printf "%.0f" .DiskTotal}}" aria-label="Disk /rec used"></progress> <span class="readout readout-sm">{{printf "%.0f" .DiskFree}}<span class="readout-unit">GB</span></span> free of {{printf "%.0f" .DiskTotal}} GB &middot; record time left <span class="readout readout-sm">{{.RecordTime}}</span>{{if .Notice}} <span class="badge badge-warning footer-notice" role="alert">{{.Notice}}</span>{{end}}`))

// webNotice/webNoticeUntil is the dashboard counterpart of sysNotice: a
// one-shot notice rendered into the page footer. startPlayback uses it
// for the sample-rate/channel refusal, which previously only reached the log.
var webNotice string
var webNoticeUntil time.Time

func showWebNotice(msg string) {
	webNotice = msg
	webNoticeUntil = time.Now().Add(6 * time.Second)
}

type statusView struct {
	Recording   bool
	Playing     bool
	Paused      bool
	Monitoring  bool
	MonOutput   bool
	Elapsed     string
	Meter       string
	Notice      string
	Format      string
	SampleRate  int
	Channels    int
	InfernoUp   bool
	DemoMode    bool
	TXStatus    string
	Uptime      string
	AppVersion  string
	CPUPerCore  []float64
	RAMApp      float64
	RAMSysUsed  float64
	RAMSysTotal float64
	CPUTemp     float64
	DiskTotal   float64
	DiskFree    float64
	DiskUsed    float64 // DiskTotal - DiskFree, for the footer's <progress>
	RecordTime  string
}

func currentStatusView() statusView {
	mutex.Lock()
	v := statusView{
		Recording:  isRecording,
		Playing:    currentState == StatePlaying,
		Paused:     currentState == StatePaused,
		Monitoring: monitoring,
		MonOutput:  monitoringOutput,
		Notice:     webNoticeIfLive(),
		Format:     "WAV",
		SampleRate: sampleRates[sampleRateIdx] / 1000,
		Channels:   channelCount,
		InfernoUp:  infernoUp(),
		DemoMode:   demoMode,
	}
	_, v.TXStatus = txStatusLocked()
	switch {
	case v.Recording:
		v.Elapsed = formatDuration(time.Since(recordStart))
		v.Meter = formatMeter()
	case v.Playing:
		v.Elapsed = formatDuration(time.Since(playbackStart))
	case v.Paused:
		v.Elapsed = formatDuration(playbackPausedElapsed)
	}
	mutex.Unlock()

	t := snapshotTelemetry()
	v.Uptime, v.AppVersion, v.CPUPerCore = t.Uptime, t.AppVersion, t.CPUPerCore
	v.RAMApp, v.RAMSysUsed, v.RAMSysTotal = t.RAMApp, t.RAMSysUsed, t.RAMSysTotal
	v.CPUTemp, v.DiskTotal, v.DiskFree, v.RecordTime = t.CPUTemp, t.DiskTotal, t.DiskFree, t.RecordTime
	v.DiskUsed = max(0, v.DiskTotal-v.DiskFree)
	return v
}

// webNoticeIfLive returns the pending dashboard notice, if any, and clears
// it once expired. Must be called with the app mutex held, like the rest of
// currentStatusView.
func webNoticeIfLive() string {
	if webNotice == "" || !time.Now().Before(webNoticeUntil) {
		webNotice = ""
		return ""
	}
	return webNotice
}

func renderStatusHTML() (string, error) {
	var buf bytes.Buffer
	if err := statusTmpl.Execute(&buf, currentStatusView()); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	// Unchecked Execute hides truncated pages on client disconnect; debug,
	// not warn, since a gone client is not an app fault.
	if err := statusTmpl.Execute(w, currentStatusView()); err != nil {
		logDebugf("status render: %v", err)
	}
}

// telemetryHistView is the dashboard graphs' feed: parallel arrays, newest
// last, sampled every teleHistStep (see appendTelemetryHist).
type telemetryHistView struct {
	T      []int64     `json:"t"`
	CPU    []float64   `json:"cpu"`
	Cores  [][]float64 `json:"cores"`
	RAMApp []float64   `json:"ramApp"`
	RAMSys []float64   `json:"ramSys"`
	Temp   []float64   `json:"temp"`
	Disk   []float64   `json:"disk"`
	// SubNames labels the columns of Sub, the app's CPU by subsystem in %
	// of one core (see threadcpu.go).
	SubNames []string    `json:"subNames"`
	Sub      [][]float64 `json:"sub"`
}

func currentTelemetryHist() telemetryHistView {
	mutex.Lock()
	defer mutex.Unlock()
	return telemetryHistView{
		T:        append([]int64(nil), teleHistT...),
		CPU:      append([]float64(nil), teleHistCPU...),
		Cores:    append([][]float64(nil), teleHistCores...),
		RAMApp:   append([]float64(nil), teleHistRAMApp...),
		RAMSys:   append([]float64(nil), teleHistRAMSys...),
		Temp:     append([]float64(nil), teleHistTemp...),
		Disk:     append([]float64(nil), teleHistDisk...),
		SubNames: cpuSubsystems,
		Sub:      append([][]float64(nil), teleHistSub...),
	}
}

func handleAPITelemetry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(currentTelemetryHist()); err != nil {
		logDebugf("telemetry encode: %v", err)
	}
}

// teleWSHub tracks dashboard telemetry sockets; guarded by teleWSMu (never
// the app mutex - broadcast renders status HTML which takes it).
var teleWSHub = map[*websocket.Conn]bool{}
var teleWSMu sync.Mutex

// teleWSMessage is the hx-ws wire shape: target selects the swap element,
// content is HTML for #diskInfo (the footer) or the history JSON for #teleHist.
type teleWSMessage struct {
	Target  string `json:"target"`
	Content string `json:"content"`
}

func teleWSSend(ws *websocket.Conn, target, content string) bool {
	if err := ws.SetWriteDeadline(time.Now().Add(wsWriteTimeout)); err != nil {
		return false
	}
	return websocket.JSON.Send(ws, teleWSMessage{Target: target, Content: content}) == nil
}

// buildTelemetryWSMessages renders one broadcast round: status HTML plus the
// history JSON payload. Factored for tests (no socket needed).
func buildTelemetryWSMessages() (status, hist string, err error) {
	status, err = renderStatusHTML()
	if err != nil {
		return "", "", err
	}
	raw, err := json.Marshal(currentTelemetryHist())
	if err != nil {
		return "", "", err
	}
	return status, string(raw), nil
}

func broadcastTelemetry() {
	status, hist, err := buildTelemetryWSMessages()
	if err != nil {
		return
	}
	// Snapshot the client set under lock, then send without it: holding
	// teleWSMu across blocking socket writes lets one slow/vanished
	// dashboard stall every connect/disconnect plus the panel render's wait
	// on the app mutex. A client that connects mid-tick simply joins the
	// next one 2s later; one that disconnects mid-tick gets a harmless
	// redundant Close+delete (both idempotent).
	teleWSMu.Lock()
	config, recs, configChanged, recsChanged := panelWSMessages()
	clients := make([]*websocket.Conn, 0, len(teleWSHub))
	for ws := range teleWSHub {
		clients = append(clients, ws)
	}
	teleWSMu.Unlock()
	for _, ws := range clients {
		alive := true
		if !wsSessionLive(ws) {
			alive = false // logged out or token rotated: stop streaming
		} else if !teleWSSend(ws, "#diskInfo", status) || !teleWSSend(ws, "#teleHist", hist) {
			alive = false
		} else if configChanged && !teleWSSend(ws, "#config", config) {
			alive = false
		} else if recsChanged && !teleWSSend(ws, "#recordings", recs) {
			alive = false
		}
		if !alive {
			teleWSMu.Lock()
			ws.Close()
			delete(teleWSHub, ws)
			teleWSMu.Unlock()
		}
	}
}

// lastPanelConfig/lastPanelRecs are the last pushed panel bodies; the
// Status and Recordings panels only go out over the socket when they
// actually changed, so an idle dashboard costs no re-renders. Guarded by
// teleWSMu - panelWSMessages renders (taking the app mutex inside), so
// never call it with the app mutex already held.
var lastPanelConfig, lastPanelRecs string

// lastPanelRecsKey is the take-set fingerprint the stored recordings body was
// rendered from. Empty until the first successful render.
var lastPanelRecsKey string

// panelWSMessages renders both panels, stores the new bodies, and reports
// whether each changed since the last push. Call with teleWSMu held.
func panelWSMessages() (config, recs string, configChanged, recsChanged bool) {
	if c, err := renderConfigHTML(); err == nil {
		config, configChanged = c, c != lastPanelConfig
		lastPanelConfig = c
	}
	// The row render opens and reads every WAV for its duration, so skip it
	// when the take set hasn't changed. recordingFilesKey fingerprints the
	// set from directory mtimes - the same key recordingFiles() itself
	// trusts for cache invalidation, so this is exactly as fresh as the
	// data source (and shares its documented blind spot: in-place content
	// edits without mtime change). That blind spot includes a take being
	// written: appending to a file leaves its directory's mtime alone, so
	// the live row's duration froze. A live take therefore never skips, and
	// the flag is in the key so the row renders once more after Stop.
	// The playback selection is part of the key: it marks a row.
	mutex.Lock()
	sel := selectedPlayback
	mutex.Unlock()
	live := takeLive.Load()
	suffix := fmt.Sprintf("|%s|%t", sel, live)
	if recKey, ok := recordingFilesKey(); ok && !live && recKey+suffix == lastPanelRecsKey && lastPanelRecsKey != "" {
		return config, lastPanelRecs, configChanged, false
	}
	if r, err := renderRecordingsHTMLLimit(latestRecsPushCap); err == nil {
		recs, recsChanged = r, r != lastPanelRecs
		lastPanelRecs = r
		if key, ok := recordingFilesKey(); ok {
			lastPanelRecsKey = key + suffix
		}
	}
	return config, recs, configChanged, recsChanged
}

func handleWSTelemetry(ws *websocket.Conn) {
	teleWSMu.Lock()
	teleWSHub[ws] = true
	teleWSMu.Unlock()
	defer func() {
		teleWSMu.Lock()
		delete(teleWSHub, ws)
		teleWSMu.Unlock()
		ws.Close()
	}()
	// Instant first paint so a fresh dashboard never waits a full tick:
	// status + history plus both panels (a new socket hasn't seen anything,
	// so send unconditionally - this also seeds the change cache).
	if status, hist, err := buildTelemetryWSMessages(); err == nil {
		if !teleWSSend(ws, "#diskInfo", status) || !teleWSSend(ws, "#teleHist", hist) {
			return
		}
	}
	teleWSMu.Lock()
	config, recs, _, _ := panelWSMessages()
	teleWSMu.Unlock()
	if config != "" && !teleWSSend(ws, "#config", config) {
		return
	}
	if recs != "" && !teleWSSend(ws, "#recordings", recs) {
		return
	}
	// Read to EOF purely to notice the client going away; frames are ignored.
	var discard any
	for {
		if websocket.JSON.Receive(ws, &discard) != nil {
			return
		}
	}
}

func telemetryWSLoop() {
	ticker := time.NewTicker(teleHistStep)
	defer ticker.Stop()
	for range ticker.C {
		broadcastTelemetry()
	}
}

// handleAPIMeter is deliberately separate from handleAPIStatus: the VU
// hologram needs numeric dB values on a fast (~150ms) push to look live,
// while the 2s telemetry-socket push is fine for everything else on the
// dashboard. meterPeakDB/meterRMSDB fall back to meterSilence whenever nothing is
// recording (see main.go's stopRecording/meterReader), so the hologram
// correctly goes quiet rather than showing a stale level.
// channelLevel is one meter: PeakDB the instantaneous peak, HoldDB the
// held peak (the OLED's ballistics, decayPeakHold: held for the Peak Hold
// setting, then falling at 20 dB/s), RMSDB the level.
type channelLevel struct {
	PeakDB float64 `json:"peakDB"`
	HoldDB float64 `json:"holdDB"`
	RMSDB  float64 `json:"rmsDB"`
}

type meterResponse struct {
	PeakDB     float64        `json:"peakDB"`
	RMSDB      float64        `json:"rmsDB"`
	Recording  bool           `json:"recording"`
	Playing    bool           `json:"playing"`
	Paused     bool           `json:"paused"`
	Monitoring bool           `json:"monitoring"`
	MonOutput  bool           `json:"monOutput"`
	InfernoUp  bool           `json:"infernoUp"`
	Elapsed    string         `json:"elapsed"`
	Channels   []channelLevel `json:"channels"`
	FloorDB    float64        `json:"floorDB"`
	// DisplaySeq is the OLED framebuffer generation (see render) so the
	// dashboard mirror reloads on change instead of polling blindly.
	DisplaySeq uint64 `json:"displaySeq"`
	// TXStatus is the inferno transmit state (see txholder.go), pushed live
	// so the dashboard tracks clock loss without a status refresh.
	TXStatus string `json:"txStatus"`
	// TXShort is the same state in the Status table's short form.
	TXShort string `json:"txShort"`
	// ChannelNames label the meter strips: the unit's RX channel names as
	// a network controller named them (channelnames.go).
	ChannelNames []string `json:"channelNames"`
	// Timecode is the timecode input, output and chase (tcweb.go).
	Timecode tcMeterView `json:"timecode"`
}

// jsonSafeDB coerces a dB level to a JSON-encodable value. encoding/json will
// not marshal +/-Inf or NaN (the WebSocket meter and /api/meter would then
// return an empty 200 instead of a payload), so clamp any non-finite reading
// to the silence sentinel before it reaches the wire. meterReader in main.go
// already sanitizes at ingestion, but this guarantees the JSON sink can never
// fail even if a non-finite value comes from some other path (meter math,
// decay ballistics, etc.).
func jsonSafeDB(v float64) float64 {
	if math.IsInf(v, 0) || math.IsNaN(v) {
		return meterSilence
	}
	return v
}

// currentMeterResponse builds a meterResponse snapshot under the app mutex -
// shared by the plain-HTTP /api/meter handler (kept for anything that wants
// a one-shot read) and the /ws/meter push loop below, so there's exactly
// one place that assembles this payload.
// currentMeterResponse is the meter snapshot plus the strips' channel
// names, which are read (cached) without the app mutex.
func currentMeterResponse() meterResponse {
	resp := buildMeterLevels()
	resp.ChannelNames = displayChannelNames(len(resp.Channels))
	resp.Timecode = currentTimecodeStatus()
	return resp
}

// buildMeterLevels takes the app mutex for the levels and transport state.
func buildMeterLevels() meterResponse {
	mutex.Lock()
	defer mutex.Unlock()

	resp := meterResponse{
		PeakDB:     jsonSafeDB(meterPeakDB),
		RMSDB:      jsonSafeDB(meterRMSDB),
		Recording:  isRecording,
		Playing:    currentState == StatePlaying,
		Paused:     currentState == StatePaused,
		Monitoring: monitoring,
		MonOutput:  monitoringOutput,
		InfernoUp:  infernoUp(),
		FloorDB:    vuRangeOptions[vuRangeIdx],
		DisplaySeq: displaySeq,
	}
	resp.TXShort, resp.TXStatus = txStatusLocked()
	// Always size the meter bank to the configured channel count. During
	// recording, the peak/RMS arrays are exactly channelCount (startRecording
	// sizes them to it), and at idle/monitoring they follow it too, so this
	// is normally a no-op - but while a channel change is still in flight
	// (Inferno restart is deferred if a take is running), sizing to
	// channelCount means the VU count tracks the setting immediately instead
	// of staying pinned to the old running server. The per-index bounds
	// checks below keep channels beyond the current arrays silent rather
	// than reading out of range.
	count := channelCount
	resp.Channels = make([]channelLevel, count)
	for i := range resp.Channels {
		c := channelLevel{PeakDB: meterSilence, HoldDB: meterSilence, RMSDB: meterSilence}
		if i < len(meterChannelPeakHeld) && i < len(meterChannelRMS) {
			c.HoldDB, c.RMSDB = jsonSafeDB(meterChannelPeakHeld[i]), jsonSafeDB(meterChannelRMS[i])
			c.PeakDB = c.HoldDB
			if i < len(meterChannelPeak) {
				c.PeakDB = jsonSafeDB(meterChannelPeak[i])
			}
		}
		resp.Channels[i] = c
	}
	switch {
	case resp.Recording:
		resp.Elapsed = formatDuration(time.Since(recordStart))
	case resp.Playing:
		resp.Elapsed = formatDuration(time.Since(playbackStart))
	case resp.Paused:
		resp.Elapsed = formatDuration(playbackPausedElapsed)
	}
	return resp
}

// meterCache shares one marshaled snapshot across meter sockets: without it
// N dashboards each build (up to 128 channels) and marshal identical payloads
// at 10Hz. The payload is time-quantized to the tick anyway (Elapsed), so a
// 100ms TTL loses nothing. Guarded by its own small mutex, never the app
// mutex, so a slow snapshot build can't stall render/input. On marshal
// failure (unreachable for this struct, but cheap to honor) the last good
// frame keeps serving rather than pushing an empty one clients would choke on.
var meterCacheMu sync.Mutex
var meterCacheAt time.Time
var meterCachePayload []byte

const meterCacheTTL = 100 * time.Millisecond

func cachedMeterPayload() []byte {
	meterCacheMu.Lock()
	defer meterCacheMu.Unlock()
	if meterCachePayload != nil && time.Since(meterCacheAt) < meterCacheTTL {
		return meterCachePayload
	}
	data, err := json.Marshal(currentMeterResponse())
	if err != nil {
		logDebugf("meter marshal: %v", err)
		return meterCachePayload
	}
	meterCachePayload = data
	meterCacheAt = time.Now()
	return data
}

func handleAPIMeter(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(currentMeterResponse()); err != nil {
		logDebugf("meter encode: %v", err)
	}
}

// handleWSMeter pushes a meter snapshot every 100ms over a WebSocket rather
// than making the dashboard poll /api/meter - fewer requests, and headroom
// to tighten the interval later without adding HTTP request overhead per
// tick. Falls back to nothing fancier than closing on the first send error
// (client navigated away, network dropped) - the dashboard's reconnect
// logic (see the WS setup in dashboardTmpl) is what handles that, not this
// loop retrying.
// wsWriteTimeout bounds how long a single meter-frame write may block. It's
// a var so tests can tighten it.
var wsWriteTimeout = 5 * time.Second

// wsMeterSend pushes one meter snapshot, arming a fresh write deadline first.
// It returns false when the connection is done and the push loop should exit.
// The deadline matters: a client that vanishes without closing (power loss,
// silent network drop) never triggers a read error, and a deadline-less Send
// can block on it indefinitely - leaking this goroutine per stale connection
// and keeping the connection "active" so remoteControlLoop's Shutdown can't
// drain it (a clean close by the client errors the write immediately; the
// deadline covers the silent-vanish case at the cost of one timed-out write).
func wsMeterSend(ws *websocket.Conn) bool {
	if err := ws.SetWriteDeadline(time.Now().Add(wsWriteTimeout)); err != nil {
		return false
	}
	return websocket.JSON.Send(ws, json.RawMessage(cachedMeterPayload())) == nil
}

func handleWSMeter(ws *websocket.Conn) {
	defer ws.Close()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		if !wsSessionLive(ws) || !wsMeterSend(ws) {
			return
		}
	}
}

// wsSessionLive reports whether the login session that opened ws is still
// valid. requireAuth checks only the handshake, so a socket used to keep
// streaming after a logout, the session's expiry, or a token rotation -
// the response to a compromised token - had revoked it.
func wsSessionLive(ws *websocket.Conn) bool {
	r := ws.Request()
	return r != nil && validSession(r)
}

func handleAPIRecordStart(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	// Use the same gate as the physical Record button so the WebUI can't
	// start a take that the hardware would refuse (low disk, or from a state
	// other than idle) - see startRecordingGuarded.
	startRecordingGuarded()
	mutex.Unlock()
	handleAPIStatus(w, r)
}

func handleAPIRecordStop(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	if isRecording {
		stopRecording()
	}
	mutex.Unlock()
	handleAPIStatus(w, r)
}

func handleAPIMonitorStart(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	autoMonitor = true
	startMonitor()
	mutex.Unlock()
	handleAPIStatus(w, r)
}

func handleAPIMonitorStop(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	if monitoring {
		autoMonitor = false
		stopMonitor()
	}
	mutex.Unlock()
	handleAPIStatus(w, r)
}

var recordingsTmpl = template.Must(template.New("recordings").Parse(`
<div class="recordings-wrap scroll">
<table class="table is-sticky">
<thead><tr><th></th><th>File</th><th>Tracks</th><th>Channels</th><th>Format</th><th>Start</th><th>End</th><th>Duration</th><th></th></tr></thead>
<tbody>
{{if not .Rows}}<tr><td colspan="9"><div class="empty-state"><span class="empty-state-icon">&#8709;</span><span class="empty-state-title">None yet.</span><span class="empty-state-hint">Takes appear here as they finalize.</span></div></td></tr>{{else}}
{{range .Rows}}<tr{{if .Selected}} class="is-selected" aria-selected="true"{{end}}>
<td class="recs-play"><form hx-post="/api/playback/select" hx-target="#recordings" hx-swap="innerHTML"><input type="hidden" name="file" value="{{.RelPath}}"><button class="btn btn-sm btn-secondary" type="submit" title="Load this take: PLAY starts it" aria-label="Load {{.Name}} for playback"><svg class="icon" aria-hidden="true"><use href="{{$.Sprite}}#icon-play"/></svg></button></form></td>
<td>{{.Name}}{{if .Selected}} <span class="badge badge-accent">loaded</span>{{end}}</td>
<td>{{.Channels}}</td>
<td class="recs-chans"><details><summary title="Channel names of this take (from the unit's inferno channel names when it started; rename here - the unit itself is not changed)">{{.ChanSummary}}</summary>
<form hx-post="/api/recordings/channels" hx-target="#recordings" hx-swap="innerHTML" class="chan-form"><input type="hidden" name="file" value="{{.RelPath}}">
{{range .ChanNames}}<label class="chan-row"><span>{{.Number}}</span><input class="input" name="name_{{.Number}}" value="{{.Name}}" maxlength="32" required>{{if .Source}}<small title="Source when the take started">&larr; {{.Source}}</small>{{end}}</label>
{{end}}<button class="btn btn-sm" type="submit">Save names</button></form></details></td>
<td>{{.Format}} {{.RateKHz}}kHz</td>
<td>{{.StartStr}}</td>
<td>{{.EndStr}}</td>
<td>{{.DurationStr}}</td>
<td class="recs-dl"><a class="btn btn-sm btn-secondary" href="/download/{{.RelPath}}" download><svg class="icon" aria-hidden="true"><use href="{{$.Sprite}}#icon-download"/></svg> download</a></td>
</tr>{{end}}
{{end}}
</tbody>
</table>
{{if .Capped}}<p class="recs-note">Showing latest {{len .Rows}} of {{.Total}} takes.</p>{{end}}
</div>
`))

type recordingsView struct {
	Rows   []recordingRow
	Total  int
	Capped bool
	Sprite string
}

type recordingRow struct {
	Name        string
	RelPath     string
	Selected    bool // the take Play starts (see playselect.go)
	ChanNames   []recChannel
	ChanSummary string
	Channels    int
	Format      string
	SampleRate  int
	StartStr    string
	EndStr      string
	DurationStr string
}

func rateKHz(hz int) string            { return strconv.FormatFloat(float64(hz)/1000, 'f', -1, 64) }
func (r recordingRow) RateKHz() string { return rateKHz(r.SampleRate) }

func buildRecordingRow(path string) recordingRow {
	name := filepath.Base(path)
	row := recordingRow{Name: name}
	// RelPath is the path relative to RecordPath (e.g. "2026-08-30/Live_...wav"),
	// the unique key for download - recordingFiles() globs both the top level
	// and per-day subfolders, so basename alone could collide across days.
	if rel, err := filepath.Rel(RecordPath, path); err == nil {
		row.RelPath = rel
	} else {
		row.RelPath = name
	}

	meta := readTakeMetadata(path)
	// Preserve the legacy presentation/validation gate until its separate fix.
	if !meta.Filename.StartValid {
		return row
	}
	start := meta.Filename.Start
	channels, sampleRate := meta.Channels, meta.SampleRate
	format := meta.Filename.Format

	row.Channels = channels
	row.ChanNames = meta.ChannelNames
	row.ChanSummary = channelSummary(row.ChanNames)
	row.SampleRate = sampleRate
	row.Format = format
	row.StartStr = start.Format("2006-01-02 15:04:05")

	// Keep the exact Hz rate for validation and duration; format kHz only for display.
	dur := meta.Duration
	if dur > 0 {
		row.DurationStr = formatDuration(dur)
		row.EndStr = start.Add(dur).Format("2006-01-02 15:04:05")
	} else {
		row.DurationStr = "-"
		row.EndStr = "-"
	}
	return row
}

func handleAPIRecordings(w http.ResponseWriter, r *http.Request) {
	html, err := renderRecordingsHTML()
	if err != nil {
		http.Error(w, "recordings unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// renderRecordingsHTML renders the dashboard recordings list; shared by the
// one-shot GET (initial paint) and the telemetry-socket push.
// latestRecs caps the pushed render (0 = all): the list re-renders on every
// telemetry tick while recording (the in-progress take's duration grows),
// so hundreds of takes would resend a large table every 2s. The push shows
// the newest takes with a count note; the explicit GET renders everything.
const latestRecsPushCap = 50

func renderRecordingsHTML() (string, error) {
	return renderRecordingsHTMLLimit(0)
}

func renderRecordingsHTMLLimit(limit int) (string, error) {
	files := recordingFiles()
	// Oldest first by each take's start time from its name, so the cap keeps
	// the newest: glob order is by filename, where the prefix sorts ahead of
	// the time. Unparsable names sort first; ties keep their glob order.
	start := make(map[string]string, len(files))
	for _, f := range files {
		if m := recFilenameRe.FindStringSubmatch(filepath.Base(f)); m != nil {
			start[f] = m[2] + m[3]
		}
	}
	slices.SortStableFunc(files, func(a, b string) int { return strings.Compare(start[a], start[b]) })
	view := recordingsView{Total: len(files), Sprite: iconSpriteHref(currentTheme())}
	if limit > 0 && len(files) > limit {
		files = files[len(files)-limit:]
		view.Capped = true
	}
	mutex.Lock()
	sel := selectedPlayback
	mutex.Unlock()
	for _, f := range files {
		row := buildRecordingRow(f)
		row.Selected = f == sel
		view.Rows = append(view.Rows, row)
	}
	var buf bytes.Buffer
	if err := recordingsTmpl.Execute(&buf, view); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// handleDownload only serves files that appear in the app's own current
// recordingFiles() listing - whitelisting against reality rather than just
// filepath.Base()-sanitizing the request, so a path like "../../etc/passwd"
// is rejected outright rather than relying on string-cleaning alone. It keys
// on the path relative to RecordPath (the recordingRow.RelPath the list uses
// for its download link), which is unique even though the basename may be
// shared across per-day subfolders.
func handleDownload(w http.ResponseWriter, r *http.Request) {
	rel := r.PathValue("filepath")
	if rel == "" || strings.Contains(rel, "..") {
		http.NotFound(w, r)
		return
	}
	for _, f := range recordingFiles() {
		if relPath, err := filepath.Rel(RecordPath, f); err == nil && relPath == rel {
			// Never serve the take currently being written: it would be a
			// growing, half-finalized WAV (same rule as the USB copy loop).
			mutex.Lock()
			active := isRecording && f == recordingFile
			mutex.Unlock()
			if active {
				http.NotFound(w, r)
				return
			}
			// attachment: browsers otherwise open a WAV in their own
			// player instead of saving it.
			w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(f)}))
			http.ServeFile(w, r, f)
			return
		}
	}
	http.NotFound(w, r)
}

// handleDownloadAll streams every finished recording as a single ZIP bundle,
// with a small manifest.txt describing each file. It never loads the files
// into memory - each one is opened and copied into the archive as it's
// encountered - so a very large set (multi-channel high-sample-rate takes can
// be many GB each) is written to the client streaming, not buffered. Zip entry
// names use the recording's path relative to RecordPath (the same unique key
// the list uses for per-file download), so per-day subfolders are preserved
// and same-named files across days don't collide.
func handleDownloadAll(w http.ResponseWriter, r *http.Request) {
	// Snapshot the in-progress take under lock, then filter before any
	// headers go out: the bundle must never include the half-written WAV
	// (torn read, mid-write duration), and pre-statting keeps the manifest's
	// file count honest instead of skipping unreadables mid-stream.
	mutex.Lock()
	active := ""
	if isRecording {
		active = recordingFile
	}
	mutex.Unlock()
	var files []string
	for _, f := range recordingFiles() {
		if f == active {
			continue
		}
		if info, err := os.Stat(f); err != nil || info.IsDir() {
			continue
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		// A bare 404 reads as "broken" - the common case is simply an empty
		// /rec (fresh unit, or a dev box). Say so, with a way back.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><head><title>Download ALL</title></head><body>`+
			`<p>No recordings to download yet.</p>`+
			`<p><a href="/">Back to dashboard</a></p></body></html>`)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="pi9696-recordings-%s.zip"`, time.Now().Format("20060102_150405")))

	if err := writeRecordingZip(w, RecordPath, files); err != nil {
		logErrorf("download-all: %v", err)
	}
}

// writeRecordingZip streams every file in files as a single ZIP archive with a
// manifest.txt describing each one. Each file is opened and copied into the
// archive as it's encountered, never buffered whole, so a very large set
// (multi-channel high-sample-rate takes can be many GB each) is written
// streaming. Zip entry names use each file's path relative to base (the
// recording root), so per-day subfolders are preserved and same-named files
// across days don't collide. base is the path prefix against which rel is
// computed; it's a parameter so the same streaming logic is testable against a
// temp directory without touching the real RecordPath.
func writeRecordingZip(dst io.Writer, base string, files []string) (err error) {
	zw := zip.NewWriter(dst)
	// Close writes the central directory; without it the archive is
	// unreadable. Its error used to be dropped, so a client that went away
	// at the very end was never logged as a failed download.
	defer func() {
		if cerr := zw.Close(); err == nil {
			err = cerr
		}
	}()

	// The manifest goes in last, so its header can state what the archive
	// really holds: a take deleted or unreadable between the caller's
	// listing and its turn here is skipped, and the headers have long been
	// sent by then, so the manifest is the only place to tell the user.
	var manifest strings.Builder
	var skipped []string
	added := 0
	fmt.Fprintf(&manifest, "%-60s %12s %8s %6s %8s %10s  %s\n", "Path", "Size(bytes)", "Channels", "Rate", "Format", "Duration", "Start")

	for _, f := range files {
		rel, err := filepath.Rel(base, f)
		if err != nil || strings.Contains(rel, "..") {
			continue
		}
		entry := filepath.ToSlash(rel)

		info, err := os.Stat(f)
		if err != nil {
			logErrorf("download-all: skipping %s: %v", entry, err)
			skipped = append(skipped, fmt.Sprintf("%s (%v)", entry, err))
			continue
		}

		// Open before writing the entry header: opening after it left an
		// empty entry in the archive for a file that could not be read.
		in, err := os.Open(f)
		if err != nil {
			logErrorf("download-all: skipping %s: %v", entry, err)
			skipped = append(skipped, fmt.Sprintf("%s (%v)", entry, err))
			continue
		}
		// PCM WAV is incompressible noise to Deflate: Store skips the
		// CPU burn and streams multi-GB takes at disk speed instead.
		hdr := &zip.FileHeader{Name: entry, Method: zip.Store, Modified: info.ModTime()}
		wc, err := zw.CreateHeader(hdr)
		if err != nil {
			in.Close()
			return err
		}
		_, copyErr := io.Copy(wc, in)
		in.Close()
		if copyErr != nil {
			return copyErr
		}
		added++

		row := buildRecordingRow(f)
		fmt.Fprintf(&manifest, "%-60s %12d %8d %6s %8s %10s  %s\n",
			entry, info.Size(), row.Channels, row.RateKHz(), row.Format, row.DurationStr, row.StartStr)
		// The take's channel names: listed in the manifest, and the
		// sidecar itself goes in the bundle next to the take.
		chans := recordingChannels(f)
		for _, c := range chans {
			src := ""
			if c.Source != "" {
				src = "  <- " + c.Source
			}
			fmt.Fprintf(&manifest, "    ch%-3d %s%s\n", c.Number, c.Name, src)
		}
		if side, err := os.ReadFile(channelsSidecar(f)); err == nil {
			hdr := &zip.FileHeader{Name: strings.TrimSuffix(entry, filepath.Ext(entry)) + ".channels.json", Method: zip.Deflate, Modified: info.ModTime()}
			if w, err := zw.CreateHeader(hdr); err == nil {
				w.Write(side)
			}
		}
	}

	var head strings.Builder
	fmt.Fprintf(&head, "PI9696 recording bundle\nGenerated: %s\nFiles: %d\n", time.Now().Format("2006-01-02 15:04:05"), added)
	if len(skipped) > 0 {
		fmt.Fprintf(&head, "INCOMPLETE: %d of %d recordings could not be read and are missing:\n", len(skipped), added+len(skipped))
		for _, s := range skipped {
			fmt.Fprintf(&head, "    %s\n", s)
		}
	}
	head.WriteString("\n")
	mw, err := zw.Create("manifest.txt")
	if err != nil {
		return err
	}
	if _, err := mw.Write([]byte(head.String() + manifest.String())); err != nil {
		return err
	}
	return nil
}

//go:embed web/htmax.min.js web/uPlot.iife.min.js web/uPlot.min.css
var embeddedWeb embed.FS

// Theme bundles come from the ftl-themes submodule rather than web/: they are
// version-pinned with the repo instead of downloaded at install time, so the
// dashboard cannot end up serving a theme that disagrees with this binary.
// Each dist/<slug>.css is self-contained (reset + components + app shell +
// theme); the fonts sit alongside because a bundle references them as
// ../assets/fonts/... relative to its own served path.
//
//go:embed third_party/ftl-themes/dist/*.css third_party/ftl-themes/dist/themes.json third_party/ftl-themes/dist/icons/*.svg third_party/ftl-themes/assets/fonts/*.woff2
var embeddedThemes embed.FS

// serveEmbeddedStatic serves a pinned vendored asset with immutable caching,
// from whichever embedded set holds it (web/ for the vendored JS/CSS,
// third_party/ for the theme bundles and their fonts).
func serveEmbeddedStatic(w http.ResponseWriter, r *http.Request, src embed.FS, path, contentType string) {
	data, err := src.ReadFile(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(data)
}

func newRemoteMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /manifest.json", handleManifest)
	mux.HandleFunc("GET /icon.svg", handleIcon)
	mux.HandleFunc("GET /login", handleLoginGet)
	mux.HandleFunc("POST /login", handleLoginPost)
	mux.HandleFunc("POST /logout", requireAuth(handleLogout))
	// State change lives on POST (logout-CSRF via top-level navigation);
	// plain GETs just land back on the dashboard.
	mux.HandleFunc("GET /logout", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}))
	mux.HandleFunc("GET /", requireAuth(handleDashboard))
	mux.HandleFunc("GET /api/settings/panes", requireAuth(handleSettingsPanes))
	mux.HandleFunc("GET /api/status", requireAuth(handleAPIStatus))
	mux.HandleFunc("GET /api/telemetry", requireAuth(handleAPITelemetry))
	mux.HandleFunc("GET /api/meter", requireAuth(handleAPIMeter))
	mux.HandleFunc("GET /ws/meter", requireAuth(websocket.Handler(handleWSMeter).ServeHTTP))
	mux.HandleFunc("GET /ws/telemetry", requireAuth(websocket.Handler(handleWSTelemetry).ServeHTTP))
	registerTimecodeRoutes(mux, requireAuth)
	mux.HandleFunc("GET /api/config", requireAuth(handleAPIConfig))
	mux.HandleFunc("POST /api/device-name", requireAuth(handleAPIDeviceName))
	mux.HandleFunc("POST /api/settings/vu-range", requireAuth(handleAPISettingsVURange))
	mux.HandleFunc("POST /api/settings/peak-hold", requireAuth(handleAPISettingsPeakHold))
	mux.HandleFunc("POST /api/settings/log-level", requireAuth(handleAPISettingsLogLevel))
	mux.HandleFunc("POST /api/settings/theme", requireAuth(handleAPISettingsTheme))
	mux.HandleFunc("POST /api/settings/tint", requireAuth(handleAPISettingsTint))
	registerDisplayOptionRoutes(mux)
	mux.HandleFunc("POST /api/settings/brightness", requireAuth(handleAPISettingsBrightness))
	mux.HandleFunc("POST /api/settings/dim", requireAuth(handleAPISettingsAutoDim))
	mux.HandleFunc("POST /api/settings/demo", requireAuth(handleAPISettingsDemoMode))
	mux.HandleFunc("POST /api/settings/rotate-token", requireAuth(handleAPIRotateToken))
	mux.HandleFunc("POST /api/settings/hyperdeck", requireAuth(handleAPISettingsHyperdeck))
	mux.HandleFunc("POST /api/settings/monitor", requireAuth(handleAPISettingsMonitor))
	mux.HandleFunc("POST /api/settings/sample-rate", requireAuth(handleAPISettingsSampleRate))
	mux.HandleFunc("POST /api/settings/channels", requireAuth(handleAPISettingsChannels))
	mux.HandleFunc("POST /api/settings/tag", requireAuth(handleAPISettingsTag))
	mux.HandleFunc("POST /api/settings/prefix", requireAuth(handleAPISettingsPrefix))
	mux.HandleFunc("POST /api/settings/transport-mode", requireAuth(handleAPISettingsTransportMode))
	mux.HandleFunc("POST /api/settings/wifi", requireAuth(handleAPISettingsWiFi))
	mux.HandleFunc("POST /api/config/export", requireAuth(handleAPIConfigExport))
	mux.HandleFunc("POST /api/config/import", requireAuth(handleAPIConfigImport))
	mux.HandleFunc("POST /api/record/start", requireAuth(handleAPIRecordStart))
	mux.HandleFunc("POST /api/record/stop", requireAuth(handleAPIRecordStop))
	mux.HandleFunc("POST /api/monitor/start", requireAuth(handleAPIMonitorStart))
	mux.HandleFunc("POST /api/monitor/stop", requireAuth(handleAPIMonitorStop))
	mux.HandleFunc("GET /api/recordings", requireAuth(handleAPIRecordings))
	mux.HandleFunc("POST /api/playback/select", requireAuth(handleAPIPlaybackSelect))
	mux.HandleFunc("GET /api/recordings/channels", requireAuth(handleAPIRecordingChannels))
	mux.HandleFunc("POST /api/recordings/channels", requireAuth(handleAPIRecordingChannels))
	mux.HandleFunc("POST /api/channels/label", requireAuth(handleAPIChannelLabel))
	mux.HandleFunc("GET /download-all", requireAuth(handleDownloadAll))
	mux.HandleFunc("GET /download/{filepath...}", requireAuth(handleDownload))

	mux.HandleFunc("GET /api/display.png", requireAuth(handleDisplayPNG))
	mux.HandleFunc("POST /api/input/encoder/left", requireAuth(handleInputEncoderRotate(-1)))
	mux.HandleFunc("POST /api/input/encoder/right", requireAuth(handleInputEncoderRotate(1)))
	mux.HandleFunc("POST /api/input/encoder/click", requireAuth(handleInputEncoderClick))
	mux.HandleFunc("POST /api/input/encoder/hold", requireAuth(handleInputEncoderHold))
	mux.HandleFunc("POST /api/input/button/record", requireAuth(handleInputButton(hardware.RecordButton)))
	mux.HandleFunc("POST /api/input/button/stop", requireAuth(handleInputButton(hardware.StopButton)))
	mux.HandleFunc("POST /api/input/button/play", requireAuth(handleInputButton(hardware.PlayButton)))

	// htmax.min.js (htmx 4.0 plus its bundled extensions) is vendored at
	// install time (pinned to 4.0.1) rather than referencing an
	// external CDN at runtime - this device shouldn't depend on internet
	// access, only its own LAN, to serve its control page. Embedded so the
	// page works no matter what directory the binary runs from (the old
	// relative web/ path 404d everything outside the service's
	// WorkingDirectory); immutable cache headers since the bytes are pinned.
	mux.HandleFunc("GET /static/htmax.min.js", func(w http.ResponseWriter, r *http.Request) {
		serveEmbeddedStatic(w, r, embeddedWeb, "web/htmax.min.js", "text/javascript")
	})
	mux.HandleFunc("GET /static/uPlot.iife.min.js", func(w http.ResponseWriter, r *http.Request) {
		serveEmbeddedStatic(w, r, embeddedWeb, "web/uPlot.iife.min.js", "text/javascript")
	})
	mux.HandleFunc("GET /static/uPlot.min.css", func(w http.ResponseWriter, r *http.Request) {
		serveEmbeddedStatic(w, r, embeddedWeb, "web/uPlot.min.css", "text/css")
	})

	// Theme bundles and their fonts, served as siblings (/static/themes/x.css
	// resolves ../assets/fonts/... to /static/assets/fonts/...), which is the
	// layout ftl-themes' CONTRACT.md requires. Only a slug that exists in the
	// embedded set is served, so a stale or hand-typed slug 404s rather than
	// escaping the embed with a traversal.
	// A ServeMux wildcard must span a whole path segment, so the ".css" is
	// matched here rather than in the pattern.
	mux.HandleFunc("GET /static/themes/{file}", func(w http.ResponseWriter, r *http.Request) {
		slug, ok := strings.CutSuffix(r.PathValue("file"), ".css")
		// core.css is the always-linked reset+components file, not a
		// theme bundle; it serves alongside the themes it lacks.
		if !ok || (slug != "core" && !isKnownTheme(slug)) {
			http.NotFound(w, r)
			return
		}
		serveEmbeddedStatic(w, r, embeddedThemes, themeAssetPath("dist/"+slug+".css"), "text/css")
	})
	// Per-theme icon sprites (dist/icons/<slug>.svg, merged by the library's
	// build from generic + theme overrides) and the generic fallback.
	mux.HandleFunc("GET /static/themes/icons/{file}", func(w http.ResponseWriter, r *http.Request) {
		slug, ok := strings.CutSuffix(r.PathValue("file"), ".svg")
		if !ok || (slug != "generic" && !isKnownTheme(slug)) {
			http.NotFound(w, r)
			return
		}
		serveEmbeddedStatic(w, r, embeddedThemes, themeAssetPath("dist/icons/"+slug+".svg"), "image/svg+xml")
	})
	mux.HandleFunc("GET /static/assets/fonts/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !strings.HasSuffix(name, ".woff2") || strings.ContainsAny(name, "/\\") {
			http.NotFound(w, r)
			return
		}
		serveEmbeddedStatic(w, r, embeddedThemes, themeAssetPath("assets/fonts/"+name), "font/woff2")
	})

	return mux
}

// remoteControlPort is the TCP port the control surface binds to. 8080 by
// default; override with PI9696_REMOTE_PORT for a host that fronts the UI on
// the standard HTTP port instead. Read once at startup, like the bind address.
func remoteControlPort() string {
	if p := os.Getenv("PI9696_REMOTE_PORT"); p != "" {
		return p
	}
	return "8080"
}

// startRemoteServer binds to the given address (normally "0.0.0.0" from
// remoteControlLoop, or a specific host via PI9696_REMOTE_BIND for dev
// testing). Binding 0.0.0.0 serves the control surface on every interface -
// the Round 3 design decision, replacing the old eth0-only constraint; access
// is still gated by the token/session auth.
func startRemoteServer(ip string) (*http.Server, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(ip, remoteControlPort()))
	if err != nil {
		return nil, err
	}

	srv := newRemoteHTTPServer()
	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			logErrorf("Remote control server error: %v", err)
		}
	}()

	logInfof("Remote control server listening on http://%s", listener.Addr())
	return srv, nil
}

// remoteHeaderTimeout and remoteIdleTimeout bound what a client can hold
// open without doing anything: the server had no timeouts at all, so a
// client trickling request headers (or parking idle keep-alives) kept a
// connection and its goroutine forever. Vars so tests can shrink them.
// Deliberately no Read/WriteTimeout: Download-all streams multi-GB bodies
// and the WebSockets live for the session.
var (
	remoteHeaderTimeout = 10 * time.Second
	remoteIdleTimeout   = 2 * time.Minute
)

// newRemoteHTTPServer builds the WebUI server.
//
// ErrorLog bypasses slog: net/http reports recovered handler panics
// through it, and the default (log -> slog at Info) is dropped by the
// Error-only default level - a panic holding the app mutex would then
// wedge the whole WebUI with nothing in the journal.
func newRemoteHTTPServer() *http.Server {
	return &http.Server{
		Handler:           newRemoteMux(),
		ErrorLog:          log.New(os.Stderr, "http: ", 0),
		ReadHeaderTimeout: remoteHeaderTimeout,
		IdleTimeout:       remoteIdleTimeout,
	}
}

// anyInterfaceIP returns the first non-loopback IPv4 address on any up
// interface, or "" if none. This is the "serve on any interface" view that
// the eth0-only NetworkDetector can't give: the remote control server must
// run whenever *any* interface (eth0, wlan0 AP/client, USB gadget, etc.) has
// an address, not just eth0 (Round 3 design decision).
func anyInterfaceIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip := ipnet.IP.To4()
				if ip != nil && !ip.IsLoopback() {
					return ip.String()
				}
			}
		}
	}
	return ""
}

// remoteControlLoop (re)binds the remote control server to every up interface
// (0.0.0.0) and tears it down when no interface has an address, mirroring
// networkMonitorLoop's polling approach but kept entirely separate from the
// app mutex: binding/shutting down a listener is not instant, and this must
// never block render()/input handling the way pre-worker Inferno start/stop
// used to.
func remoteControlLoop() {
	var currentServer *http.Server
	var wasUp bool

	for {
		up := anyInterfaceIP() != ""
		if up != wasUp {
			if currentServer != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				err := currentServer.Shutdown(ctx)
				cancel()
				if err != nil {
					// Graceful drain timed out - long-lived connections
					// (the WebSocket meter push, a dashboard that stopped
					// reading) don't count as idle. Force-close so a
					// stopped interface can't leave the old server's
					// connections half-open; their handlers exit on the
					// resulting write errors.
					currentServer.Close()
				}
				currentServer = nil
				setRemoteServer(nil)
				logInfof("Remote control server stopped")
			}

			wasUp = up
			if up {
				srv, err := startRemoteServer("0.0.0.0")
				if err != nil {
					logErrorf("Failed to start remote control server: %v", err)
					wasUp = false // retry on the next tick
				} else {
					currentServer = srv
					setRemoteServer(srv)
				}
			}
		}

		time.Sleep(5 * time.Second)
	}
}

// remoteServerMu guards remoteServer, the currently bound control server
// (if any). Published by remoteControlLoop so gracefulShutdown can stop
// accepting new requests before it drains transport.
var remoteServerMu sync.Mutex
var remoteServer *http.Server

func setRemoteServer(srv *http.Server) {
	remoteServerMu.Lock()
	remoteServer = srv
	remoteServerMu.Unlock()
}

// closeRemoteServer stops the control server if one is bound: no new
// connections, in-flight handlers drained briefly, then force-closed.
func closeRemoteServer() {
	remoteServerMu.Lock()
	srv := remoteServer
	remoteServer = nil
	remoteServerMu.Unlock()
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	err := srv.Shutdown(ctx)
	cancel()
	if err != nil {
		srv.Close()
	}
}

// remoteAccessInfo is what Settings -> Remote Access shows on the OLED.
// It picks any reachable address (not just eth0) since the server now binds
// every interface.
func remoteAccessInfo() []string {
	ip := anyInterfaceIP()
	if ip == "" {
		return []string{"Remote Access", "Not available", "(no interface has an IP)"}
	}
	return []string{
		"Remote Access",
		fmt.Sprintf("http://%s:%s", ip, remoteControlPort()),
		"Token: " + formatToken(remoteToken),
	}
}
