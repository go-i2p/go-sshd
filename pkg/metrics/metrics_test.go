package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockLogger implements a minimal logger for testing
type mockLogger struct {
	*logrus.Logger
}

func newMockLogger() *mockLogger {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress output during tests
	return &mockLogger{Logger: logger}
}

func TestNewCollector(t *testing.T) {
	logger := newMockLogger()
	collector := NewCollector(logger.Logger)

	assert.NotNil(t, collector, "Collector should not be nil")
	assert.NotNil(t, collector.registry, "Registry should be initialized")
	assert.NotNil(t, collector.activeSessions, "Active sessions map should be initialized")
	assert.Equal(t, 0, len(collector.activeSessions), "Should start with no active sessions")
}

func TestRecordConnection(t *testing.T) {
	logger := newMockLogger()
	collector := NewCollector(logger.Logger)

	// Record multiple connections
	collector.RecordConnection()
	collector.RecordConnection()
	collector.RecordConnection()

	// Verify active connections counter
	assert.Equal(t, 3, collector.activeConnections, "Should track 3 active connections")
}

func TestRecordConnectionClose(t *testing.T) {
	logger := newMockLogger()
	collector := NewCollector(logger.Logger)

	// Record connection and close
	collector.RecordConnection()
	assert.Equal(t, 1, collector.activeConnections, "Should have 1 active connection")

	duration := 5 * time.Second
	collector.RecordConnectionClose(duration)

	assert.Equal(t, 0, collector.activeConnections, "Should have 0 active connections after close")
}

func TestRecordAuthAttempt(t *testing.T) {
	logger := newMockLogger()
	collector := NewCollector(logger.Logger)

	tests := []struct {
		method string
		result string
	}{
		{"publickey", "success"},
		{"publickey", "failure"},
		{"password", "success"},
		{"password", "failure"},
	}

	for _, tt := range tests {
		t.Run(tt.method+"_"+tt.result, func(t *testing.T) {
			// Should not panic
			collector.RecordAuthAttempt(tt.method, tt.result)
		})
	}
}

func TestRecordSessionLifecycle(t *testing.T) {
	logger := newMockLogger()
	collector := NewCollector(logger.Logger)

	// Start session
	sessionID := "session-123"
	startTime := collector.RecordSessionStart(sessionID)

	assert.NotZero(t, startTime, "Start time should be set")
	assert.Equal(t, 1, len(collector.activeSessions), "Should have 1 active session")

	// Small delay to ensure measurable duration
	time.Sleep(10 * time.Millisecond)

	// End session
	collector.RecordSessionEnd(sessionID)

	assert.Equal(t, 0, len(collector.activeSessions), "Should have 0 active sessions after end")
}

func TestRecordSessionEnd_NonexistentSession(t *testing.T) {
	logger := newMockLogger()
	collector := NewCollector(logger.Logger)

	// Ending a non-existent session should not panic
	collector.RecordSessionEnd("nonexistent-session")

	assert.Equal(t, 0, len(collector.activeSessions), "Should still have 0 active sessions")
}

func TestRecordBytesTransferred(t *testing.T) {
	logger := newMockLogger()
	collector := NewCollector(logger.Logger)

	// Record various data transfers
	collector.RecordBytesTransferred("sent", 1024)
	collector.RecordBytesTransferred("received", 2048)
	collector.RecordBytesTransferred("sent", 512)

	// Should not panic - actual metrics are internal to Prometheus
}

func TestRecordRequest(t *testing.T) {
	logger := newMockLogger()
	collector := NewCollector(logger.Logger)

	tests := []struct {
		requestType string
		result      string
	}{
		{"shell", "success"},
		{"sftp", "success"},
		{"forward", "success"},
		{"shell", "failure"},
	}

	for _, tt := range tests {
		t.Run(tt.requestType+"_"+tt.result, func(t *testing.T) {
			collector.RecordRequest(tt.requestType, tt.result)
		})
	}
}

func TestRecordRequestDuration(t *testing.T) {
	logger := newMockLogger()
	collector := NewCollector(logger.Logger)

	durations := []struct {
		requestType string
		duration    time.Duration
	}{
		{"shell", 100 * time.Millisecond},
		{"sftp", 5 * time.Second},
		{"forward", 50 * time.Millisecond},
	}

	for _, d := range durations {
		t.Run(d.requestType, func(t *testing.T) {
			collector.RecordRequestDuration(d.requestType, d.duration)
		})
	}
}

func TestGetHealth(t *testing.T) {
	logger := newMockLogger()
	collector := NewCollector(logger.Logger)

	tests := []struct {
		name         string
		setup        func()
		configValid  bool
		wantStatus   string
		wantConns    int
		wantSessions int
	}{
		{
			name:         "Healthy with no activity",
			setup:        func() {},
			configValid:  true,
			wantStatus:   "ok",
			wantConns:    0,
			wantSessions: 0,
		},
		{
			name: "Healthy with active connections",
			setup: func() {
				collector.RecordConnection()
				collector.RecordConnection()
			},
			configValid:  true,
			wantStatus:   "ok",
			wantConns:    2,
			wantSessions: 0,
		},
		{
			name: "Healthy with active sessions",
			setup: func() {
				collector.RecordSessionStart("session-1")
				collector.RecordSessionStart("session-2")
			},
			configValid:  true,
			wantStatus:   "ok",
			wantConns:    2, // From previous test
			wantSessions: 2,
		},
		{
			name:         "Degraded with invalid config",
			setup:        func() {},
			configValid:  false,
			wantStatus:   "degraded",
			wantConns:    2,
			wantSessions: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			health := collector.GetHealth(tt.configValid)

			assert.Equal(t, tt.wantStatus, health.Status, "Status should match")
			assert.Equal(t, tt.wantConns, health.ActiveConns, "Active connections should match")
			assert.Equal(t, tt.wantSessions, health.ActiveSess, "Active sessions should match")
			assert.Equal(t, tt.configValid, health.ConfigValid, "Config validity should match")

			if !tt.configValid {
				assert.NotEmpty(t, health.Message, "Should have error message when degraded")
			}
		})
	}
}

func TestHandler(t *testing.T) {
	logger := newMockLogger()
	collector := NewCollector(logger.Logger)

	// Record some metrics to ensure they appear in output
	collector.RecordConnection()
	collector.RecordAuthAttempt("publickey", "success")
	collector.RecordSessionStart("test-session")

	// Get the metrics handler
	handler := collector.Handler()
	assert.NotNil(t, handler, "Handler should not be nil")

	// Create test request
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	// Serve metrics
	handler.ServeHTTP(w, req)

	// Should return 200 OK
	assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")

	// Response should contain Prometheus metrics
	body := w.Body.String()
	assert.Contains(t, body, "sshd_connections_total", "Should contain connection total metric")
	assert.Contains(t, body, "sshd_connections_active", "Should contain active connections metric")
	assert.Contains(t, body, "sshd_auth_attempts_total", "Should contain auth attempts metric")
	assert.Contains(t, body, "sshd_sessions_total", "Should contain sessions total metric")
}

func TestConcurrentAccess(t *testing.T) {
	logger := newMockLogger()
	collector := NewCollector(logger.Logger)

	// Test concurrent access to metrics
	var wg sync.WaitGroup
	concurrency := 50

	wg.Add(concurrency * 4)

	// Concurrent connections
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			collector.RecordConnection()
		}()
	}

	// Concurrent auth attempts
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			collector.RecordAuthAttempt("publickey", "success")
		}()
	}

	// Concurrent sessions
	for i := 0; i < concurrency; i++ {
		go func(id int) {
			defer wg.Done()
			sessionID := "session-" + string(rune(id))
			collector.RecordSessionStart(sessionID)
		}(i)
	}

	// Concurrent data transfers
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			collector.RecordBytesTransferred("sent", 1024)
		}()
	}

	wg.Wait()

	// Verify state is consistent
	assert.Equal(t, concurrency, collector.activeConnections, "Should have correct connection count")
	assert.Equal(t, concurrency, len(collector.activeSessions), "Should have correct session count")
}

func TestMetricsServer(t *testing.T) {
	logger := newMockLogger()
	collector := NewCollector(logger.Logger)

	// Create server with available port (use 0 for automatic assignment)
	server := NewServer(collector, "127.0.0.1:0", logger)
	require.NotNil(t, server, "Server should be created")

	// Start server
	err := server.Start()
	require.NoError(t, err, "Server should start without error")
	defer server.Stop()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Get the actual address
	addr := server.listener.Addr().String()

	// Test metrics endpoint
	resp, err := http.Get("http://" + addr + "/metrics")
	require.NoError(t, err, "Should be able to GET /metrics")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Metrics endpoint should return 200")
	resp.Body.Close()

	// Test health endpoint
	resp, err = http.Get("http://" + addr + "/health")
	require.NoError(t, err, "Should be able to GET /health")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Health endpoint should return 200")

	var health HealthStatus
	err = json.NewDecoder(resp.Body).Decode(&health)
	require.NoError(t, err, "Should decode health JSON")
	assert.Equal(t, "ok", health.Status, "Health status should be ok")
	resp.Body.Close()

	// Test ready endpoint
	resp, err = http.Get("http://" + addr + "/ready")
	require.NoError(t, err, "Should be able to GET /ready")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Ready endpoint should return 200")
	resp.Body.Close()
}

func TestHealthHandler(t *testing.T) {
	logger := newMockLogger()
	collector := NewCollector(logger.Logger)
	server := NewServer(collector, ":0", logger)

	// Add some activity
	collector.RecordConnection()
	collector.RecordSessionStart("test-session")

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	server.healthHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"), "Should return JSON")

	var health HealthStatus
	err := json.NewDecoder(w.Body).Decode(&health)
	require.NoError(t, err, "Should decode health JSON")

	assert.Equal(t, "ok", health.Status, "Status should be ok")
	assert.Equal(t, 1, health.ActiveConns, "Should have 1 active connection")
	assert.Equal(t, 1, health.ActiveSess, "Should have 1 active session")
	assert.True(t, health.ConfigValid, "Config should be valid")
}

func TestReadyHandler(t *testing.T) {
	logger := newMockLogger()
	collector := NewCollector(logger.Logger)
	server := NewServer(collector, ":0", logger)

	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()

	server.readyHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK for ready server")
	assert.Contains(t, w.Body.String(), "ready", "Should contain 'ready' text")
}
