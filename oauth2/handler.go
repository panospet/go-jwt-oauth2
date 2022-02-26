package oauth2

import "context"

type Handler interface {
	GetRedirectUrlToSignIn() string
	GetUserInfo(ctx context.Context, state string, code string) (OAuth2User, error)
}

type OAuth2User struct {
	Id         string `json:"id"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Picture    string `json:"picture"`
	Locale     string `json:"locale"`
}
