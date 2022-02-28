package oauth2

import "context"

type Handler interface {
	GetRedirectUrlToSignIn() string
	GetUserInfo(ctx context.Context, state string, code string) (OAuth2Info, error)
}

type OAuth2Info map[string]interface{}
