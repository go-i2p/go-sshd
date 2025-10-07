package signals

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestNewHandler(t *testing.T) {
	h := NewHandler()
	defer h.Stop()

	// Verify context is not cancelled initially
	select {
	case <-h.Context().Done():
		t.Error("Context should not be cancelled initially")
	default:
		// Expected behavior
	}

	// Verify we have a valid context
	if h.Context() == nil {
		t.Error("Context should not be nil")
	}
}

func TestShutdownSignal(t *testing.T) {
	h := NewHandler()
	defer h.Stop()

	// Send SIGTERM to ourselves
	go func() {
		time.Sleep(10 * time.Millisecond)
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Errorf("Failed to send SIGTERM: %v", err)
		}
	}()

	// Wait for shutdown signal
	sig := h.WaitForShutdown()
	if sig != syscall.SIGTERM {
		t.Errorf("Expected SIGTERM, got %v", sig)
	}

	// Verify context is cancelled
	select {
	case <-h.Context().Done():
		// Expected behavior
	default:
		t.Error("Context should be cancelled after shutdown signal")
	}
}

func TestReloadSignal(t *testing.T) {
	h := NewHandler()
	defer h.Stop()

	// Send SIGHUP to ourselves
	go func() {
		time.Sleep(10 * time.Millisecond)
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Errorf("Failed to send SIGHUP: %v", err)
		}
	}()

	// Wait for reload signal
	sig := h.WaitForReload()
	if sig != syscall.SIGHUP {
		t.Errorf("Expected SIGHUP, got %v", sig)
	}

	// Verify context is NOT cancelled for reload
	select {
	case <-h.Context().Done():
		t.Error("Context should not be cancelled after reload signal")
	default:
		// Expected behavior
	}
}

func TestProgrammaticShutdown(t *testing.T) {
	h := NewHandler()
	defer h.Stop()

	// Trigger shutdown programmatically
	h.Shutdown()

	// Verify context is cancelled
	select {
	case <-h.Context().Done():
		// Expected behavior
	case <-time.After(100 * time.Millisecond):
		t.Error("Context should be cancelled after programmatic shutdown")
	}

	// WaitForShutdown should return nil for programmatic shutdown
	sig := h.WaitForShutdown()
	if sig != nil {
		t.Errorf("Expected nil signal for programmatic shutdown, got %v", sig)
	}
}

func TestContextCancellation(t *testing.T) {
	h := NewHandler()
	defer h.Stop()

	ctx := h.Context()

	// Cancel context and verify it's cancelled
	h.Shutdown()

	select {
	case <-ctx.Done():
		// Expected behavior
	case <-time.After(100 * time.Millisecond):
		t.Error("Context should be cancelled")
	}

	// Verify context error
	if ctx.Err() == nil {
		t.Error("Context should have an error after cancellation")
	}
}

func TestStop(t *testing.T) {
	h := NewHandler()

	// Stop the handler
	h.Stop()

	// Verify context is cancelled
	select {
	case <-h.Context().Done():
		// Expected behavior
	default:
		t.Error("Context should be cancelled after Stop()")
	}

	// Sending signals after Stop() should not panic
	// Note: We can't easily test that signals are no longer handled
	// without potentially affecting other tests, so we just verify
	// that Stop() doesn't panic and cancels the context.
}

func TestConcurrentOperations(t *testing.T) {
	h := NewHandler()
	defer h.Stop()

	// Test concurrent access to context
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			ctx := h.Context()
			if ctx == nil {
				t.Error("Context should not be nil")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Expected
		case <-time.After(100 * time.Millisecond):
			t.Error("Timeout waiting for concurrent operations")
		}
	}
}