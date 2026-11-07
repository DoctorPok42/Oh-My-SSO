package notify

import (
	"context"
	"errors"
	"testing"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Notify drops an event when the queue is full; NotifyWait waits. Without
// it, an import of a thousand users would lose every invitation past the
// size of the queue, without a word.
func TestNotifyWaitWaitsForRoomInTheQueue(t *testing.T) {
	d := NewDispatcher(DispatcherConfig{QueueSize: 1}, DispatcherDeps{})
	event := domain.NotificationEvent{Kind: domain.NotificationAccountInvite}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.NotifyWait(ctx, event); err != nil {
		t.Fatalf("room in the queue: %v", err)
	}

	sent := make(chan error, 1)
	go func() { sent <- d.NotifyWait(ctx, event) }()
	select {
	case err := <-sent:
		t.Fatalf("returned with a full queue: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	<-d.queue // a worker takes the first e-mail
	select {
	case err := <-sent:
		if err != nil {
			t.Fatalf("room came: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still waiting with room in the queue")
	}
	if len(d.queue) != 1 {
		t.Errorf("queue holds %d events, want 1", len(d.queue))
	}
}

func TestNotifyWaitGivesUp(t *testing.T) {
	d := NewDispatcher(DispatcherConfig{QueueSize: 1}, DispatcherDeps{})
	event := domain.NotificationEvent{Kind: domain.NotificationAccountInvite}
	if err := d.NotifyWait(context.Background(), event); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.NotifyWait(ctx, event); !errors.Is(err, context.Canceled) {
		t.Errorf("full queue, context over: %v", err)
	}

	<-d.queue
	d.Close(context.Background())
	if err := d.NotifyWait(context.Background(), event); err == nil {
		t.Error("accepted by a closed dispatcher")
	}
}

type countingAudit struct {
	repository.AuditLogRepository
	entries int
}

func (a *countingAudit) Create(context.Context, repository.CreateAuditLogParams) (*domain.AuditLog, error) {
	a.entries++
	return &domain.AuditLog{}, nil
}

// A batch stays out of the audit log, except for what went wrong.
func TestQuietAuditOnlyKeepsFailures(t *testing.T) {
	for name, c := range map[string]struct {
		quiet bool
		err   error
		want  int
	}{
		"an e-mail":             {false, nil, 1},
		"an e-mail that failed": {false, errors.New("smtp"), 1},
		"one of a batch":        {true, nil, 0},
		"one that failed":       {true, errors.New("smtp"), 1},
	} {
		audit := &countingAudit{}
		d := NewDispatcher(DispatcherConfig{}, DispatcherDeps{Audit: audit})
		d.writeAudit(context.Background(), domain.NotificationEvent{QuietAudit: c.quiet}, "a@b.example", TemplateAccountInvite, 1, c.err)
		if audit.entries != c.want {
			t.Errorf("%s: %d entries, want %d", name, audit.entries, c.want)
		}
	}
}
