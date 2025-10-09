package metrics

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// Collector manages SSH server metrics using Prometheus client library.
// This is a thin wrapper around prometheus client_golang providing SSH-specific metrics.
// Library: prometheus/client_golang v1.x (industry standard, zero custom protocol implementation)
type Collector struct {
	// Connection metrics
	connectionsTotal   prometheus.Counter
	connectionsActive  prometheus.Gauge
	connectionDuration prometheus.Histogram

	// Authentication metrics
	authAttemptsTotal *prometheus.CounterVec

	// Session metrics
	sessionsActive prometheus.Gauge
	sessionsTotal  prometheus.Counter

	// Data transfer metrics
	bytesTransferred *prometheus.CounterVec

	// Request metrics (SFTP, shell commands, forwarding)
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec

	registry          *prometheus.Registry
	logger            *logrus.Logger
	mu                sync.RWMutex
	activeSessions    map[string]time.Time // sessionID -> start time
	activeConnections int                  // Track for health checks
}

// NewCollector creates a new metrics collector with Prometheus registry.
// Uses prometheus/client_golang for all metric collection and exposition.
func NewCollector(logger *logrus.Logger) *Collector {
	registry := prometheus.NewRegistry()

	c := &Collector{
		// Connection metrics
		connectionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sshd_connections_total",
			Help: "Total number of SSH connections accepted",
		}),
		connectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sshd_connections_active",
			Help: "Current number of active SSH connections",
		}),
		connectionDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "sshd_connection_duration_seconds",
			Help:    "Connection duration in seconds",
			Buckets: prometheus.DefBuckets, // Standard buckets: 0.005s to 10s
		}),

		// Authentication metrics (labeled by method and result)
		authAttemptsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sshd_auth_attempts_total",
				Help: "Total authentication attempts by method and result",
			},
			[]string{"method", "result"}, // method: publickey, password; result: success, failure
		),

		// Session metrics
		sessionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sshd_sessions_active",
			Help: "Current number of active SSH sessions (shell, sftp, etc)",
		}),
		sessionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sshd_sessions_total",
			Help: "Total number of SSH sessions started",
		}),

		// Data transfer metrics (labeled by direction)
		bytesTransferred: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sshd_bytes_transferred_total",
				Help: "Total bytes transferred through SSH server",
			},
			[]string{"direction"}, // direction: sent, received
		),

		// Request metrics (labeled by type: shell, sftp, forward)
		requestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sshd_requests_total",
				Help: "Total number of SSH requests by type",
			},
			[]string{"type", "result"}, // type: shell, sftp, forward; result: success, failure
		),
		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "sshd_request_duration_seconds",
				Help:    "Request duration in seconds by type",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"type"},
		),

		registry:       registry,
		logger:         logger,
		activeSessions: make(map[string]time.Time),
	}

	// Register all metrics with the registry
	registry.MustRegister(
		c.connectionsTotal,
		c.connectionsActive,
		c.connectionDuration,
		c.authAttemptsTotal,
		c.sessionsActive,
		c.sessionsTotal,
		c.bytesTransferred,
		c.requestsTotal,
		c.requestDuration,
	)

	return c
}

// RecordConnection increments total and active connection counts.
// Call this when a new SSH connection is accepted.
func (c *Collector) RecordConnection() {
	c.connectionsTotal.Inc()
	c.connectionsActive.Inc()

	c.mu.Lock()
	c.activeConnections++
	c.mu.Unlock()
}

// RecordConnectionClose decrements active connections and records duration.
// Call this when an SSH connection is closed.
func (c *Collector) RecordConnectionClose(duration time.Duration) {
	c.connectionsActive.Dec()
	c.connectionDuration.Observe(duration.Seconds())

	c.mu.Lock()
	c.activeConnections--
	c.mu.Unlock()
}

// RecordAuthAttempt records an authentication attempt with method and result.
// method: "publickey", "password"; result: "success", "failure"
func (c *Collector) RecordAuthAttempt(method, result string) {
	c.authAttemptsTotal.WithLabelValues(method, result).Inc()
}

// RecordSessionStart records the start of a new session (shell, SFTP, etc).
// Returns the current time for duration calculation on close.
func (c *Collector) RecordSessionStart(sessionID string) time.Time {
	c.mu.Lock()
	startTime := time.Now()
	c.activeSessions[sessionID] = startTime
	c.mu.Unlock()

	c.sessionsTotal.Inc()
	c.sessionsActive.Inc()
	return startTime
}

// RecordSessionEnd records the end of a session and its duration.
func (c *Collector) RecordSessionEnd(sessionID string) {
	c.mu.Lock()
	startTime, exists := c.activeSessions[sessionID]
	delete(c.activeSessions, sessionID)
	c.mu.Unlock()

	c.sessionsActive.Dec()

	if exists {
		duration := time.Since(startTime)
		c.logger.WithFields(logrus.Fields{
			"session_id": sessionID,
			"duration":   duration,
		}).Debug("Session ended")
	}
}

// RecordBytesTransferred records data transfer volume.
// direction: "sent", "received"
func (c *Collector) RecordBytesTransferred(direction string, bytes int64) {
	c.bytesTransferred.WithLabelValues(direction).Add(float64(bytes))
}

// RecordRequest records a request (shell, sftp, forward) with result.
// requestType: "shell", "sftp", "forward"; result: "success", "failure"
func (c *Collector) RecordRequest(requestType, result string) {
	c.requestsTotal.WithLabelValues(requestType, result).Inc()
}

// RecordRequestDuration records request duration by type.
func (c *Collector) RecordRequestDuration(requestType string, duration time.Duration) {
	c.requestDuration.WithLabelValues(requestType).Observe(duration.Seconds())
}

// Handler returns an HTTP handler for Prometheus metrics exposition.
// This uses promhttp.HandlerFor from prometheus/client_golang (zero custom implementation).
func (c *Collector) Handler() http.Handler {
	return promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// HealthStatus represents the health check result
type HealthStatus struct {
	Status      string `json:"status"` // "ok", "degraded", "error"
	ActiveConns int    `json:"active_conns"`
	ActiveSess  int    `json:"active_sessions"`
	ConfigValid bool   `json:"config_valid"`
	Message     string `json:"message,omitempty"`
}

// GetHealth returns current health status for health check endpoints.
// This is a simple status aggregation, not a monitoring protocol implementation.
func (c *Collector) GetHealth(configValid bool) HealthStatus {
	c.mu.RLock()
	activeSessions := len(c.activeSessions)
	activeConns := c.activeConnections
	c.mu.RUnlock()

	status := HealthStatus{
		Status:      "ok",
		ActiveConns: activeConns,
		ActiveSess:  activeSessions,
		ConfigValid: configValid,
	}

	if !configValid {
		status.Status = "degraded"
		status.Message = "Configuration validation failed"
	}

	return status
}
