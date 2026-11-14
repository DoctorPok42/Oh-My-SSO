// Package valkeytest helps the tests of the degraded mode (internal/cache/
// fallback) cut Valkey off: only tests import it.
package valkeytest

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Proxy forwards TCP connections to a target until Down: the connections
// are then cut and new ones refused, as when Valkey stops, until Up.
type Proxy struct {
	target string
	addr   string

	mu    sync.Mutex
	ln    net.Listener
	conns map[net.Conn]struct{}
}

// NewProxy listens on a free local port and forwards to target (host:port).
func NewProxy(t testing.TB, target string) *Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{target: target, addr: ln.Addr().String(), conns: map[net.Conn]struct{}{}}
	p.serve(ln)
	t.Cleanup(p.Down)
	return p
}

// Addr is the address to give the client instead of target's.
func (p *Proxy) Addr() string { return p.addr }

// Down closes the listener and every connection: Valkey is unreachable.
func (p *Proxy) Down() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln != nil {
		_ = p.ln.Close()
		p.ln = nil
	}
	for c := range p.conns {
		_ = c.Close()
	}
	clear(p.conns)
}

// Up listens again on the same address.
func (p *Proxy) Up(t testing.TB) {
	t.Helper()
	var ln net.Listener
	var err error
	for range 50 { // the port may take a moment to be free again
		if ln, err = net.Listen("tcp", p.addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	p.serve(ln)
}

func (p *Proxy) serve(ln net.Listener) {
	p.mu.Lock()
	p.ln = ln
	p.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.forward(c)
		}
	}()
}

func (p *Proxy) forward(c net.Conn) {
	up, err := net.Dial("tcp", p.target)
	if err != nil {
		_ = c.Close()
		return
	}
	if !p.track(c, up) {
		return
	}
	go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
	_, _ = io.Copy(c, up)
	_ = c.Close()
}

// track records both ends, unless the proxy went down meanwhile.
func (p *Proxy) track(conns ...net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln == nil {
		for _, c := range conns {
			_ = c.Close()
		}
		return false
	}
	for _, c := range conns {
		p.conns[c] = struct{}{}
	}
	return true
}
