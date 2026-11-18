package notify

import (
	"context"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
)

func TestVerifySendsNothing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() { // a mail server that accepts everything and notes the commands
		var cmds []string
		defer func() { got <- strings.Join(cmds, " ") }()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tp := textproto.NewConn(conn)
		_ = tp.PrintfLine("220 test ESMTP")
		for {
			line, err := tp.ReadLine()
			if err != nil {
				return
			}
			cmds = append(cmds, strings.Fields(line)[0])
			if line == "QUIT" {
				_ = tp.PrintfLine("221 bye")
				return
			}
			_ = tp.PrintfLine("250 ok")
		}
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	s, err := NewSMTPEmailSender(SMTPConfig{Host: host, Port: p, Security: SecurityNone,
		From: "SSO <no-reply@example.com>"}, &Templates{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cmds := <-got; cmds != "EHLO QUIT" {
		t.Fatalf("the server received %q, want EHLO QUIT", cmds)
	}
}
