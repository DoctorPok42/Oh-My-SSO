package httptimeout

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var short = Timeouts{ReadHeader: 200 * time.Millisecond, Read: 200 * time.Millisecond,
	Write: 200 * time.Millisecond, Idle: 200 * time.Millisecond}

func start(t *testing.T, h http.Handler, to Timeouts) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(h)
	ts.Config = NewServer("", h, to)
	ts.Start()
	t.Cleanup(ts.Close)
	return ts
}

// closedWithin: the server closes conn before d.
func closedWithin(t *testing.T, conn net.Conn, d time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(d))
	_, err := io.Copy(io.Discard, conn)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("the server kept the connection open more than %s", d)
	}
}

func TestNewServerSetsEveryTimeout(t *testing.T) {
	for name, to := range map[string]Timeouts{"public": Public, "admin": Admin} {
		s := NewServer(":0", http.NotFoundHandler(), to)
		if s.ReadHeaderTimeout <= 0 || s.ReadTimeout <= 0 || s.WriteTimeout <= 0 || s.IdleTimeout <= 0 {
			t.Errorf("%s: a timeout is unbounded: %+v", name, to)
		}
		if s.ReadTimeout < s.ReadHeaderTimeout {
			t.Errorf("%s: Read (%s) shorter than ReadHeader (%s)", name, s.ReadTimeout, s.ReadHeaderTimeout)
		}
	}
}

// Slowloris on the body: headers sent at once, then the body never ends.
func TestSlowBodyIsCut(t *testing.T) {
	readErr := make(chan error, 1)
	ts := start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		readErr <- err
	}), short)

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\na")

	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("the handler read a body that never arrived")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the handler still waits for the body after the read timeout")
	}
	closedWithin(t, conn, 2*time.Second)
}

func TestIdleConnectionIsClosed(t *testing.T) {
	ts := start(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}), short)

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	closedWithin(t, conn, 2*time.Second) // kept alive, then idle
}

// slowHandler answers after d, and says whether its context was still alive.
func slowHandler(d time.Duration, extend bool, ctxErr chan<- error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if extend {
			Extend(w, r, 5*time.Second)
		}
		_, _ = io.ReadAll(r.Body)
		time.Sleep(d)
		ctxErr <- r.Context().Err()
		_, _ = io.WriteString(w, "done")
	})
}

func TestExtendOutlastsTheServerTimeouts(t *testing.T) {
	ctxErr := make(chan error, 1)
	ts := start(t, slowHandler(600*time.Millisecond, true, ctxErr), short)

	res, err := ts.Client().Post(ts.URL, "application/json", strings.NewReader(`{"ids":[]}`))
	if err != nil {
		t.Fatalf("the extended call was cut: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "done" {
		t.Fatalf("body = %q, want done", body)
	}
	if err := <-ctxErr; err != nil {
		t.Fatalf("the request context ended during the extended call: %v", err)
	}
}

// Without Extend, the same call cannot answer past the write timeout.
func TestWithoutExtendALongCallIsCut(t *testing.T) {
	ts := start(t, slowHandler(600*time.Millisecond, false, make(chan error, 1)), short)

	res, err := ts.Client().Post(ts.URL, "application/json", strings.NewReader(`{"ids":[]}`))
	if err == nil {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if string(body) == "done" {
			t.Fatal("the answer was written after the write timeout")
		}
	}
}

func TestExtendWithoutConnectionIsHarmless(t *testing.T) {
	rec := httptest.NewRecorder()
	Extend(rec, httptest.NewRequest(http.MethodGet, "/", nil), time.Minute)
}
