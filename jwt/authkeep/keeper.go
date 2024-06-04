package authkeep

import (
	"context"
)

type Keeper interface {
	AddAuth(ctx context.Context, userid string, auth JwtTokens) error
	FetchAuth(ctx context.Context, access Access) (string, error)
	DeleteAuthByUuid(ctx context.Context, uuid string) (int64, error)
	DeleteByAccess(ctx context.Context, access Access) error
}

type Access struct {
	Uuid   string
	UserId string
}

type Token struct {
	Value   string
	Uuid    string
	Expires int64
}

type JwtTokens struct {
	AccessToken  Token
	RefreshToken Token
}
