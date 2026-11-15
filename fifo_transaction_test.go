package main

import (
	"fmt"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func handoffTestFIFO(t *testing.T) int {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.raw")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	return fd
}

func TestFifoLayoutTimeoutCannotCommitLate(t *testing.T) {
	fd := handoffTestFIFO(t)
	mutex.Lock()
	oldMode, oldCtl, oldWait, oldRecovery := demoMode, rxFifoCtl, fifoLayoutWait, inputRecovery
	demoMode, rxFifoCtl, fifoLayoutWait = false, make(chan fifoLayoutReq), 100*time.Millisecond
	ctl := rxFifoCtl
	mutex.Unlock()
	t.Cleanup(func() {
		mutex.Lock()
		demoMode, rxFifoCtl, fifoLayoutWait, inputRecovery = oldMode, oldCtl, oldWait, oldRecovery
		mutex.Unlock()
	})

	// Forward the actual caller's request to a real fifoFeed. Its async
	// write lock holds the accepted request until AFTER the caller times out.
	f := fifoFeed{fd: fd, ctl: make(chan fifoLayoutReq, 1), async: &fifoAsync{
		queue: make(chan fifoChunk, 1), free: make(chan []byte, 1),
	}}
	f.async.mu.Lock()
	accepted, served := make(chan struct{}), make(chan struct{})
	go func() {
		req := <-ctl
		f.ctl <- req
		close(accepted)
		f.serve()
		close(served)
	}()
	result := make(chan bool, 1)
	go func() {
		mutex.Lock()
		_, ok := fifoSetLayout(true)
		mutex.Unlock()
		result <- ok
	}()
	<-accepted
	ok := <-result
	f.async.mu.Unlock()
	<-served
	if ok {
		t.Fatal("caller unexpectedly acknowledged the held switch")
	}
	if f.withTC {
		t.Fatal("timed-out request changed the real FIFO to the TIMECODE layout")
	}
}

func fifoQueuedBytes(t *testing.T, fd int) int {
	t.Helper()
	var n int32
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x541B, uintptr(unsafe.Pointer(&n))); err != 0 {
		t.Fatal(err)
	}
	return int(n)
}

func TestFifoCanceledDrainAbandonsPartialChunk(t *testing.T) {
	for _, withTC := range []bool{false, true} {
		t.Run(fmt.Sprint(withTC), func(t *testing.T) {
			fd := handoffTestFIFO(t)
			size, _, err := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), linuxFSetPipeSz, 4096)
			if err != 0 {
				t.Fatal(err)
			}
			const deviceChannels = 6
			channels := deviceChannels
			if !withTC {
				channels--
			}
			if int(size)%(channels*4) == 0 {
				t.Fatal("test requires a pipe ending partway through a frame")
			}
			f := fifoFeed{fd: fd, ctl: make(chan fifoLayoutReq), withTC: withTC}
			quit := make(chan struct{})
			defer close(quit)
			result := make(chan error, 1)
			go func() {
				// Larger than the pipe: the first syscall writes only a
				// partial chunk, ending in the middle of a multi-channel frame.
				result <- f.write(make([]byte, (int(size)/(channels*4)+8)*channels*4), quit, time.Millisecond)
			}()
			req := fifoLayoutReq{withTC: !withTC, reply: make(chan int64), cancel: make(chan struct{}), done: make(chan struct{})}
			f.ctl <- req // accepted only after the partial write fills the pipe
			waitFor(t, time.Second, "FIFO drained before cancellation", func() bool { return fifoQueuedBytes(t, fd) == 0 })
			close(req.cancel)
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(100 * time.Millisecond):
				// Release the old implementation's unconditional reply so
				// a red run does not leave its writer blocked.
				select {
				case <-req.reply:
				case <-time.After(time.Second):
					t.Fatal("writer stuck after cancellation")
				}
				<-result
				t.Error("canceled acknowledgement did not release the writer")
			}
			if f.withTC != withTC {
				t.Error("canceled switch changed the layout")
			}
			if n := fifoQueuedBytes(t, fd); n != 0 {
				t.Fatalf("drained partial chunk resumed with %d tail bytes", n)
			}
			var samples, want []int32
			for frame := 0; frame < 3; frame++ {
				for c := 0; c < deviceChannels; c++ {
					v := int32((1000+frame)<<8 | c)
					samples = append(samples, v)
					if c < channels {
						want = append(want, v)
					}
				}
			}
			b := framesAsS32LE(f.layout(samples, deviceChannels), make([]byte, len(samples)*4))
			if err := f.write(b, quit, time.Millisecond); err != nil {
				t.Fatal(err)
			}
			got := readFrames(t, fd, 3, channels)
			for i, frame := range got {
				if !equalInt32(frame, want[i*channels:(i+1)*channels]) {
					t.Fatalf("frame %d misaligned: %v", i, frame)
				}
			}
			if n := fifoQueuedBytes(t, fd); n != 0 {
				t.Fatalf("unexpected trailing bytes: %d", n)
			}
		})
	}
}

func TestFifoFullPipeWriteHonorsQuit(t *testing.T) {
	fd := handoffTestFIFO(t)
	size, _, err := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), linuxFGetPipeSz, 0)
	if err != 0 {
		t.Fatal(err)
	}
	f := fifoFeed{fd: fd, ctl: make(chan fifoLayoutReq)}
	quit := make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- f.write(make([]byte, int(size)+4096), quit, time.Millisecond) }()
	waitFor(t, time.Second, "partial FIFO write", func() bool { return fifoQueuedBytes(t, fd) > 0 })
	close(quit)
	select {
	case err := <-result:
		if err != errFifoQuit {
			t.Fatalf("write returned %v, want quit", err)
		}
	case <-time.After(time.Second):
		t.Fatal("full FIFO ignored quit")
	}
}
