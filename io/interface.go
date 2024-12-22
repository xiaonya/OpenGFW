package io

import (
	"context"
	"net"
	"time"
)

type Verdict int

const (
	// VerdictAccept accepts the packet, but continues to process the stream.
	// VerdictAccept 接受数据包。但仍会继续处理流
	VerdictAccept Verdict = iota //iota预定义符,将常量分别定义为0,1,2....
	// VerdictAcceptModify is like VerdictAccept, but replaces the packet with a new one.
	// VerdictAcceptModify 类似于 VerdictAccept，但会用新数据包替换原数据包
	VerdictAcceptModify
	// VerdictAcceptStream accepts the packet and stops processing the stream.
	// VerdictAcceptStream 接受数据包并停止处理流
	VerdictAcceptStream
	// VerdictDrop drops the packet, but does not block the stream.
	// VerdictDrop 丢弃数据包，但不阻止流
	VerdictDrop
	// VerdictDropStream drops the packet and blocks the stream.
	// VerdictDropStream 丢弃数据包并阻止流
	VerdictDropStream
)

// Packet represents an IP packet.
// Packet 表示 IP 数据包。
type Packet interface {
	// StreamID is the ID of the stream the packet belongs to.
	StreamID() uint32
	// Timestamp is the time the packet was received.
	Timestamp() time.Time
	// Data is the raw packet data, starting with the IP header.
	Data() []byte
}

// PacketCallback is called for each packet received.
// Return false to "unregister" and stop receiving packets.
// PacketCallback 在每个接收到的数据包时被调用。
// 返回 false 以“取消注册”并停止接收数据包。
type PacketCallback func(Packet, error) bool

type PacketIO interface {
	// Register registers a callback to be called for each packet received.
	// The callback should be called in one or more separate goroutines,
	// and stop when the context is cancelled.
	// Register 注册一个回调函数，该回调函数将在每个数据包接收时被调用。
	// 回调函数应在一个或多个单独的 goroutine 中调用，
	// 并在上下文被取消时停止。
	Register(context.Context, PacketCallback) error
	// SetVerdict sets the verdict for a packet.
	// 设置数据包的处理方式
	SetVerdict(Packet, Verdict, []byte) error
	// ProtectedDialContext is like net.DialContext, but the connection is "protected"
	// in the sense that the packets sent/received through the connection must bypass
	// the packet IO and not be processed by the callback.
	// ProtectedDialContext 类似于 net.DialContext，但连接是“受保护的”，
	// 因为通过该连接发送/接收的数据包必须绕过数据包 IO，不会被回调处理。
	ProtectedDialContext(ctx context.Context, network, address string) (net.Conn, error)
	// Close closes the packet IO.
	Close() error
	// SetCancelFunc gives packet IO access to context cancel function, enabling it to
	// trigger a shutdown
	// SetCancelFunc 使数据包 IO 能够访问上下文的取消函数，从而触发关闭操作
	SetCancelFunc(cancelFunc context.CancelFunc) error
}

type ErrInvalidPacket struct {
	Err error
}

func (e *ErrInvalidPacket) Error() string {
	return "invalid packet: " + e.Err.Error()
}
