package main

import (
	"os/exec"
	"testing"
)

func TestNonPumpStopDoesNotRetainCommand(t *testing.T) {
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	markStopRequested(cmd)
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if !takeStopRequested(cmd) {
		t.Fatal("requested exit was not recognized")
	}
	if pumpHalted(cmd) {
		t.Fatal("completed non-pump command retained a pump stop marker")
	}
}
