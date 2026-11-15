package main

import (
	"io"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type loginBodyGate struct {
	io.Reader
	entered, release chan struct{}
	once             sync.Once
}

func (b *loginBodyGate) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.release })
	return b.Reader.Read(p)
}
func TestOldTokenLoginCannotSurviveConcurrentRotation(t *testing.T) {
	oldToken, oldLimit, oldSessions := remoteToken, loginLimit, sessions
	remoteToken = "ABCDEFGH"
	loginLimit = newLoginLimiter()
	sessions = newSessionStore()
	defer func() { remoteToken, loginLimit, sessions = oldToken, oldLimit, oldSessions }()
	b := &loginBodyGate{Reader: strings.NewReader("token=ABCDEFGH"), entered: make(chan struct{}), release: make(chan struct{})}
	r := httptest.NewRequest("POST", "/login", b)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { handleLoginPost(w, r); close(done) }()
	<-b.entered
	loginLimit.mu.Lock()
	locked := true
	defer func() {
		if locked {
			loginLimit.mu.Unlock()
		}
		<-done
	}()
	close(b.release)
	waitFor(t, 3*time.Second, "login compared token and waits to record success", func() bool {
		buf := make([]byte, 1<<18)
		n := runtime.Stack(buf, true)
		return strings.Contains(string(buf[:n]), "(*loginLimiter).recordSuccess")
	})
	handleAPIRotateToken(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/settings/rotate-token", nil))
	loginLimit.mu.Unlock()
	locked = false
	<-done
	for _, c := range w.Result().Cookies() {
		if c.Name == remoteSessionCookie && sessions.valid(c.Value) {
			t.Error("old-token login minted a valid 12-hour session after rotation finished")
		}
	}
}
