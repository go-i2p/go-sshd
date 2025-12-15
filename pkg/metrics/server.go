package metrics

import (
	"encoding/json"
	"net"
	"net/http"
	"time"
)

// Server provides HTTP endpoints for metrics and health checks.
// This is a thin wrapper around http.Server for serving Prometheus metrics.
type Server struct {
	collector  *Collector
	httpServer *http.Server
	listener   net.Listener
	logger     interface {
		Infof(format string, args ...interface{})
		Errorf(format string, args ...interface{})
	}
}

// NewServer creates a new metrics server with the given collector and address.
// Uses standard library http.Server - zero custom HTTP implementation.
func NewServer(collector *Collector, addr string, logger interface {
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
},
) *Server {
	mux := http.NewServeMux()

	server := &Server{
		collector: collector,
		logger:    logger,
		httpServer: &http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}

	// Register endpoints
	mux.Handle("/metrics", collector.Handler())
	mux.HandleFunc("/health", server.healthHandler)
	mux.HandleFunc("/ready", server.readyHandler)

	return server
}

// Start begins serving metrics and health check endpoints.
// Returns immediately and serves in the background.
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return err
	}
	s.listener = listener

	s.logger.Infof("Metrics server listening on %s", s.httpServer.Addr)
	s.logger.Infof("  - Prometheus metrics: http://%s/metrics", s.httpServer.Addr)
	s.logger.Infof("  - Health check: http://%s/health", s.httpServer.Addr)
	s.logger.Infof("  - Readiness check: http://%s/ready", s.httpServer.Addr)

	go func() {
		if err := s.httpServer.Serve(s.listener); err != nil && err != http.ErrServerClosed {
			s.logger.Errorf("Metrics server error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the metrics server.
func (s *Server) Stop() error {
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}

// healthHandler returns detailed health status as JSON.
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	// For now, always consider config valid. This will be enhanced when
	// integrated with the actual server's config validation state.
	health := s.collector.GetHealth(true)

	w.Header().Set("Content-Type", "application/json")

	// Set HTTP status based on health status
	switch health.Status {
	case "ok":
		w.WriteHeader(http.StatusOK)
	case "degraded":
		w.WriteHeader(http.StatusOK) // Still responding
	case "error":
		w.WriteHeader(http.StatusServiceUnavailable)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}

	json.NewEncoder(w).Encode(health)
}

// readyHandler returns 200 OK if the server is ready to accept connections.
// This is simpler than health check and suitable for Kubernetes readiness probes.
func (s *Server) readyHandler(w http.ResponseWriter, r *http.Request) {
	health := s.collector.GetHealth(true)

	if health.Status == "error" {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("not ready\n"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ready\n"))
}
