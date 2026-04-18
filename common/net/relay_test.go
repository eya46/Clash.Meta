package net

import (
	"io"
	"net"
	"testing"
	"time"
)

type panicReadConn struct {
	net.Conn
}

func (c panicReadConn) Read(_ []byte) (int, error) {
	panic("panic read for relay test")
}

func TestRelayRecoversFromCopyPanic(t *testing.T) {
	leftBase, rightBase := net.Pipe()
	defer leftBase.Close()
	defer rightBase.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		Relay(panicReadConn{Conn: leftBase}, rightBase)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Relay did not return after panic")
	}
}

func TestRelayCopySafeTransfersData(t *testing.T) {
	srcRead, srcWrite := net.Pipe()
	dstRead, dstWrite := net.Pipe()
	defer srcRead.Close()
	defer srcWrite.Close()
	defer dstRead.Close()
	defer dstWrite.Close()

	done := make(chan error, 1)
	go func() {
		done <- relayCopySafe(dstWrite, srcRead)
	}()

	payload := []byte("hello relay")
	go func() {
		_, _ = srcWrite.Write(payload)
		_ = srcWrite.Close()
	}()

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(dstRead, buf); err != nil {
		t.Fatalf("read relayed payload: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("unexpected relayed payload: got %q want %q", string(buf), string(payload))
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("relayCopySafe returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relayCopySafe did not finish")
	}
}

func TestRelayTransfersBidirectionally(t *testing.T) {
	leftApp, leftRelay := net.Pipe()
	rightApp, rightRelay := net.Pipe()
	defer leftApp.Close()
	defer rightApp.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		Relay(leftRelay, rightRelay)
	}()

	leftPayload := []byte("from-left")
	rightPayload := []byte("from-right")

	leftWriteDone := make(chan error, 1)
	go func() {
		_, err := leftApp.Write(leftPayload)
		leftWriteDone <- err
	}()

	rightWriteDone := make(chan error, 1)
	go func() {
		_, err := rightApp.Write(rightPayload)
		rightWriteDone <- err
	}()

	leftRead := make([]byte, len(rightPayload))
	if _, err := io.ReadFull(leftApp, leftRead); err != nil {
		t.Fatalf("left read: %v", err)
	}
	if string(leftRead) != string(rightPayload) {
		t.Fatalf("unexpected data on left: got %q want %q", string(leftRead), string(rightPayload))
	}

	rightRead := make([]byte, len(leftPayload))
	if _, err := io.ReadFull(rightApp, rightRead); err != nil {
		t.Fatalf("right read: %v", err)
	}
	if string(rightRead) != string(leftPayload) {
		t.Fatalf("unexpected data on right: got %q want %q", string(rightRead), string(leftPayload))
	}

	select {
	case err := <-leftWriteDone:
		if err != nil {
			t.Fatalf("left write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("left write did not finish")
	}

	select {
	case err := <-rightWriteDone:
		if err != nil {
			t.Fatalf("right write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("right write did not finish")
	}

	_ = leftApp.Close()
	_ = rightApp.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Relay did not exit")
	}
}
