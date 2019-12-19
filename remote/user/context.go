package user

import "context"

type userKey struct{}

// NewContext creates a new context with user information attached.
func NewContext(ctx context.Context, u User) context.Context {
	return context.WithValue(ctx, userKey{}, u)
}

// FromContext returns the user information in ctx if it exists.
func FromContext(ctx context.Context) User {
	if u, ok := ctx.Value(userKey{}).(User); ok {
		return u
	}
	return Anonymous
}
