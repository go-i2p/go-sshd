// Package signals provides Unix signal handling for graceful shutdown and configuration reload.package signals

// This package follows Go best practices using context cancellation for clean server lifecycle management.
package signals

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// Handler manages Unix signals for server lifecycle operations.
// This provides graceful shutdown on SIGTERM/SIGINT and configuration reload on SIGHUP.
type Handler struct {
	shutdownSignals chan os.Signal
	reloadSignals   chan os.Signal
	ctx             context.Context
	cancel          context.CancelFunc
}

// NewHandler creates a new signal handler with context cancellation.
// Returns a handler that manages standard Unix daemon signals following OpenSSH behavior.
func NewHandler() *Handler {
	ctx, cancel := context.WithCancel(context.Background())

	h := &Handler{
		shutdownSignals: make(chan os.Signal, 1),
		reloadSignals:   make(chan os.Signal, 1),
		ctx:             ctx,
		cancel:          cancel,
	}

	// Register signal handlers
	// SIGTERM and SIGINT for graceful shutdown
	signal.Notify(h.shutdownSignals, syscall.SIGTERM, syscall.SIGINT)

	// SIGHUP for configuration reload (standard Unix daemon behavior)
	signal.Notify(h.reloadSignals, syscall.SIGHUP)

	return h
}

// Context returns the handler's context for use in server operations.
// This context is cancelled when a shutdown signal is received.
func (h *Handler) Context() context.Context {
	return h.ctx
}

// WaitForShutdown blocks until a shutdown signal (SIGTERM/SIGINT) is received.
// Returns the signal that triggered the shutdown for logging purposes.
func (h *Handler) WaitForShutdown() os.Signal {
	select {
	case sig := <-h.shutdownSignals:
		h.cancel() // Cancel the context to signal shutdown
		return sig
	case <-h.ctx.Done():
		return nil // Context cancelled elsewhere
	}
}

// WaitForReload blocks until a reload signal (SIGHUP) is received.
// This is used for configuration reload without stopping the server.
func (h *Handler) WaitForReload() os.Signal {
	select {
	case sig := <-h.reloadSignals:
		return sig
	case <-h.ctx.Done():
		return nil // Context cancelled, server shutting down
	}
}

// Shutdown triggers a graceful shutdown by cancelling the context.
// This can be called programmatically to initiate shutdown without a signal.
func (h *Handler) Shutdown() {
	h.cancel()
}

// Stop releases signal handling resources and cancels the context.
// This should be called when the handler is no longer needed.
func (h *Handler) Stop() {
	signal.Stop(h.shutdownSignals)
	signal.Stop(h.reloadSignals)
	close(h.shutdownSignals)
	close(h.reloadSignals)
	h.cancel()
}
