package auth

import "context"

type Authenticator interface {
	// AuthSelf authenticates the target PPP connection, err==nil if it's successful
	AuthSelf(ctx context.Context, username, password string) error
}
