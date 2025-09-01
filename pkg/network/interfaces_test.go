package network

import (
	"net"
	"testing"
	"time"
)

// mockAddr implements net.Addr interface for testing.
type mockAddr struct {
	network string
	address string
}

func (m mockAddr) Network() string { return m.network }
func (m mockAddr) String() string  { return m.address }

// mockConn implements net.Conn interface for testing.
type mockConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (m mockConn) Read(b []byte) (n int, err error)  { return 0, nil }
func (m mockConn) Write(b []byte) (n int, err error) { return len(b), nil }
func (m mockConn) Close() error                      { return nil }
func (m mockConn) LocalAddr() net.Addr               { return m.localAddr }
func (m mockConn) RemoteAddr() net.Addr              { return m.remoteAddr }

// Implement other net.Conn methods with minimal implementations for testing
func (m mockConn) SetDeadline(t time.Time) error      { return nil }
func (m mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m mockConn) SetWriteDeadline(t time.Time) error { return nil }

// TestConnectionHandler demonstrates testing with interface types.
func TestConnectionHandler(t *testing.T) {
	// Create mock addresses using interface types
	localAddr := mockAddr{"tcp", "127.0.0.1:22"}
	remoteAddr := mockAddr{"tcp", "192.168.1.100:12345"}

	// Create mock connection implementing net.Conn interface
	mockConn := mockConn{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}

	// Test with interface type - this allows for easy mocking
	handler := NewConnectionHandler(mockConn)

	// Test that we get interface types back
	gotRemote := handler.GetRemoteAddr()
	gotLocal := handler.GetLocalAddr()

	// Verify using interface methods
	if gotRemote.String() != "192.168.1.100:12345" {
		t.Errorf("Expected remote addr '192.168.1.100:12345', got '%s'", gotRemote.String())
	}

	if gotLocal.String() != "127.0.0.1:22" {
		t.Errorf("Expected local addr '127.0.0.1:22', got '%s'", gotLocal.String())
	}
}

// mockPacketConn implements net.PacketConn interface for testing.
type mockPacketConn struct {
	localAddr net.Addr
}

func (m mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return len(p), mockAddr{"udp", "192.168.1.200:54321"}, nil
}

func (m mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}

func (m mockPacketConn) Close() error                       { return nil }
func (m mockPacketConn) LocalAddr() net.Addr                { return m.localAddr }
func (m mockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m mockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m mockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// TestPacketHandler demonstrates testing UDP-style connections with interfaces.
func TestPacketHandler(t *testing.T) {
	// Create mock packet connection
	localAddr := mockAddr{"udp", "127.0.0.1:53"}
	mockPacketConn := mockPacketConn{localAddr: localAddr}

	// Test with interface type
	handler := NewPacketHandler(mockPacketConn)

	// Test sending with interface types
	testData := []byte("test packet")
	destAddr := mockAddr{"udp", "192.168.1.100:1234"}

	n, err := handler.SendTo(testData, destAddr)
	if err != nil {
		t.Fatalf("SendTo failed: %v", err)
	}

	if n != len(testData) {
		t.Errorf("Expected to send %d bytes, sent %d", len(testData), n)
	}

	// Test receiving with interface types
	buffer := make([]byte, 1024)
	n, addr, err := handler.ReceiveFrom(buffer)
	if err != nil {
		t.Fatalf("ReceiveFrom failed: %v", err)
	}

	// Verify we get interface types back
	if addr.String() != "192.168.1.200:54321" {
		t.Errorf("Expected sender addr '192.168.1.200:54321', got '%s'", addr.String())
	}
}

// TestParseListenAddress demonstrates testing address parsing.
func TestParseListenAddress(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"127.0.0.1:22", "127.0.0.1:22"},
		{"0.0.0.0:2222", "0.0.0.0:2222"},
		{":22", ":22"},
	}

	for _, test := range tests {
		addr, err := ParseListenAddress(test.input)
		if err != nil {
			t.Errorf("ParseListenAddress(%q) failed: %v", test.input, err)
			continue
		}

		// Test that we get back a net.Addr interface
		if addr.String() != test.expected {
			t.Errorf("ParseListenAddress(%q) = %q, want %q",
				test.input, addr.String(), test.expected)
		}

		// Verify it's the correct network type
		if addr.Network() != "tcp" {
			t.Errorf("ParseListenAddress(%q) returned wrong network type: %q",
				test.input, addr.Network())
		}
	}
}

// BenchmarkConnectionHandler demonstrates performance testing with interfaces.
func BenchmarkConnectionHandler(b *testing.B) {
	localAddr := mockAddr{"tcp", "127.0.0.1:22"}
	remoteAddr := mockAddr{"tcp", "192.168.1.100:12345"}
	mockConn := mockConn{localAddr: localAddr, remoteAddr: remoteAddr}

	handler := NewConnectionHandler(mockConn)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = handler.GetRemoteAddr()
	}
}
