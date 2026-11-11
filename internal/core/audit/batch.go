package audit

import (
	"context"
	"sync"
)

// Batch gathers the audit entries of one bulk action, so that the action
// leaves a single entry (bulk.completed or bulk.interrupted) listing what it
// did item by item, instead of one entry per item, per e-mail...
//
// The bulk runner puts it in the context of its items (WithBatch); the audit
// log repository (service.BatchedAuditLog) and the e-mail dispatcher look
// for it there. Once closed it collects nothing: a late writer (an e-mail
// that fails after the end of the action) writes its own entry, tagged with
// the operation id.
type Batch struct {
	op string

	mu      sync.Mutex
	closed  bool
	current string
	entries map[string][]Entry
}

// Entry is one change made by an item of a batch.
type Entry struct {
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type,omitempty"`
	ResourceID   string                 `json:"resource_id,omitempty"`
	TargetUserID string                 `json:"target_user_id,omitempty"`
	Warning      bool                   `json:"-"`
	Details      map[string]interface{} `json:"details,omitempty"`
}

// NewBatch starts the batch of the bulk action op (its operation id).
func NewBatch(op string) *Batch {
	return &Batch{op: op, entries: map[string][]Entry{}}
}

// Operation is the operation id of the bulk action.
func (b *Batch) Operation() string { return b.op }

// Item tells which item the next entries belong to.
func (b *Batch) Item(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.current = id
}

// Add collects e for the current item. It returns false when the batch is
// closed: the caller writes the entry itself then.
func (b *Batch) Add(e Entry) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	b.entries[b.current] = append(b.entries[b.current], e)
	return true
}

// Close ends the collection and returns the entries by item id.
func (b *Batch) Close() map[string][]Entry {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return b.entries
}

type batchKey struct{}

// WithBatch returns ctx carrying b.
func WithBatch(ctx context.Context, b *Batch) context.Context {
	return context.WithValue(ctx, batchKey{}, b)
}

// BatchOf is the batch ctx carries, nil outside a bulk action.
func BatchOf(ctx context.Context) *Batch {
	b, _ := ctx.Value(batchKey{}).(*Batch)
	return b
}
