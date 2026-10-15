package mqtt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

var errBrokerDown = errors.New("mqtt: broker unavailable, waiting to reconnect")

// publisher is one connection to the depot broker. It speaks just enough MQTT
// 3.1.1 to publish at QoS 0: CONNECT, CONNACK, PUBLISH and DISCONNECT.
type publisher struct {
	addr     string
	clientID string
	user     string
	password string

	mu      sync.Mutex
	conn    net.Conn
	backoff backoff
}

func (p *publisher) publish(topic string, payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		if err := p.connect(time.Now()); err != nil {
			return err
		}
	}
	p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := p.conn.Write(encodePublish(topic, payload)); err != nil {
		p.conn.Close()
		p.conn = nil
		return fmt.Errorf("mqtt: publish to %s: %w", topic, err)
	}
	return nil
}

func (p *publisher) connect(now time.Time) error {
	if !p.backoff.ready(now) {
		return errBrokerDown
	}
	conn, err := net.DialTimeout("tcp", p.addr, 5*time.Second)
	if err != nil {
		p.backoff.failed(now)
		return fmt.Errorf("mqtt: %w", err)
	}
	conn.SetDeadline(now.Add(5 * time.Second))
	if _, err := conn.Write(encodeConnect(p.clientID, p.user, p.password)); err != nil {
		conn.Close()
		p.backoff.failed(now)
		return fmt.Errorf("mqtt: connect: %w", err)
	}
	ack := make([]byte, 4)
	if _, err := io.ReadFull(conn, ack); err != nil {
		conn.Close()
		p.backoff.failed(now)
		return fmt.Errorf("mqtt: connack: %w", err)
	}
	if ack[0] != 0x20 || ack[3] != 0 {
		conn.Close()
		p.backoff.failed(now)
		return fmt.Errorf("mqtt: broker refused %s (return code %d)", p.clientID, ack[3])
	}
	conn.SetDeadline(time.Time{})
	p.conn = conn
	p.backoff.reset()
	return nil
}

func (p *publisher) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		p.conn.Write([]byte{0xE0, 0x00}) // DISCONNECT
		p.conn.Close()
		p.conn = nil
	}
}

// encodeConnect builds CONNECT with a clean session, user name and password, and
// keep-alive off: the relay publishes often enough that the broker never idles it.
func encodeConnect(clientID, user, password string) []byte {
	body := appendString(nil, "MQTT")
	body = append(body, 4)    // protocol level: 3.1.1
	body = append(body, 0xC2) // flags: user name, password, clean session
	body = binary.BigEndian.AppendUint16(body, 0)
	body = appendString(body, clientID)
	body = appendString(body, user)
	body = appendString(body, password)
	return packet(0x10, body)
}

func encodePublish(topic string, payload []byte) []byte {
	body := appendString(nil, topic)
	return packet(0x30, append(body, payload...))
}

// packet prefixes body with the fixed header: type byte and remaining length.
func packet(header byte, body []byte) []byte {
	out := []byte{header}
	n := len(body)
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			break
		}
	}
	return append(out, body...)
}

func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}
