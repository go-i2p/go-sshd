// Package network provides network interface patterns and utilities.
// This package demonstrates the correct use of Go network interface types
// as specified in the project's network interface patterns guidelines.
//
// NOTE: This is a reference/style-guide package, not part of the server's
// runtime data path. Its exported types (ConnectionHandler, PacketHandler,
// ListenerHandler) are illustrative examples of correct vs. incorrect
// interface usage (see BadConnectionHandler and similar) and are not wired
// into cmd/, pkg/server, pkg/embedded, or pkg/handlers.
package network

import (
	"net"
)

// ConnectionHandler demonstrates proper use of net.Conn interface.
// Always use net.Conn instead of concrete types like net.TCPConn.
type ConnectionHandler struct {
	conn net.Conn // CORRECT: interface type
}

// NewConnectionHandler creates a new connection handler.
// Accepts any net.Conn implementation for maximum flexibility.
func NewConnectionHandler(conn net.Conn) *ConnectionHandler {
	return &ConnectionHandler{
		conn: conn,
	}
}

// GetRemoteAddr returns the remote address using interface type.
// Returns net.Addr interface instead of concrete address types.
func (h *ConnectionHandler) GetRemoteAddr() net.Addr {
	return h.conn.RemoteAddr() // Returns net.Addr interface
}

// GetLocalAddr returns the local address using interface type.
func (h *ConnectionHandler) GetLocalAddr() net.Addr {
	return h.conn.LocalAddr() // Returns net.Addr interface
}

// PacketHandler demonstrates proper use of net.PacketConn interface.
// Always use net.PacketConn instead of concrete types like net.UDPConn.
type PacketHandler struct {
	conn net.PacketConn // CORRECT: interface type
}

// NewPacketHandler creates a new packet handler.
func NewPacketHandler(conn net.PacketConn) *PacketHandler {
	return &PacketHandler{
		conn: conn,
	}
}

// SendTo sends data to the specified address.
// Uses net.Addr interface for address parameter.
func (h *PacketHandler) SendTo(data []byte, addr net.Addr) (int, error) {
	return h.conn.WriteTo(data, addr)
}

// ReceiveFrom receives data and returns the sender address.
// Returns net.Addr interface for maximum flexibility.
func (h *PacketHandler) ReceiveFrom(buffer []byte) (int, net.Addr, error) {
	return h.conn.ReadFrom(buffer)
}

// ListenerHandler demonstrates proper use of net.Listener interface.
type ListenerHandler struct {
	listener net.Listener // CORRECT: interface type
}

// NewListenerHandler creates a new listener handler.
func NewListenerHandler(listener net.Listener) *ListenerHandler {
	return &ListenerHandler{
		listener: listener,
	}
}

// Accept accepts connections using interface types.
func (h *ListenerHandler) Accept() (net.Conn, error) {
	return h.listener.Accept() // Returns net.Conn interface
}

// GetAddr returns the listener address using interface type.
func (h *ListenerHandler) GetAddr() net.Addr {
	return h.listener.Addr() // Returns net.Addr interface
}

// INCORRECT EXAMPLES (what NOT to do):
//
// type BadConnectionHandler struct {
//     conn *net.TCPConn  // BAD: concrete type
// }
//
// func (h *BadConnectionHandler) GetRemoteAddr() *net.TCPAddr {
//     return h.conn.RemoteAddr().(*net.TCPAddr)  // BAD: concrete type
// }
//
// type BadPacketHandler struct {
//     conn *net.UDPConn  // BAD: concrete type
// }
//
// func (h *BadPacketHandler) SendTo(data []byte, addr *net.UDPAddr) (int, error) {
//     return h.conn.WriteToUDP(data, addr)  // BAD: concrete type
// }

// NetworkConfig demonstrates proper interface usage in configuration.
type NetworkConfig struct {
	// Use interface types for addresses
	ListenAddrs []net.Addr // CORRECT: interface slice

	// For string-based configs that will be parsed later
	ListenAddrStrings []string
}

// ParseListenAddress demonstrates proper address parsing.
// Returns net.Addr interface, not concrete types.
func ParseListenAddress(addrStr string) (net.Addr, error) {
	// This function would parse the address string and return
	// the appropriate net.Addr interface implementation
	return net.ResolveTCPAddr("tcp", addrStr)
}

// CreateListener demonstrates proper listener creation.
// Returns net.Listener interface for maximum flexibility.
func CreateListener(addr net.Addr) (net.Listener, error) {
	// Use the address interface to create appropriate listener
	return net.Listen(addr.Network(), addr.String())
}
