package audit

import "context"

// Actor represents the user who performed an action. It is used for auditing purposes.
type Actor struct {
	UserID  string
	RealmID string
}

type actorCtxKey struct{}

func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorCtxKey{}, a)
}

func ActorFromContext(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorCtxKey{}).(Actor)
	return a, ok
}
