package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"

	"golang.org/x/oauth2"
)

const (
	googleUserInfoUrl = "https://www.googleapis.com/oauth2/v2/userinfo?access_token=%s"
)

type GoogleOAuthHandler struct {
	Config      *oauth2.Config
	UserInfoUrl string
	State       string
	Client      *http.Client
}

func NewGoogleOAuthHandler(cfg *oauth2.Config, client *http.Client) *GoogleOAuthHandler {
	state := randSeq(24)
	return &GoogleOAuthHandler{
		Config: cfg,
		Client: client,
		State:  state,
	}
}

func (o *GoogleOAuthHandler) GetRedirectUrlToSignIn() string {
	return o.Config.AuthCodeURL(o.State)
}

func (o *GoogleOAuthHandler) GetUserInfo(ctx context.Context, state string, code string) (OAuth2Info, error) {
	if state != o.State {
		return OAuth2Info{}, fmt.Errorf("invalid oauth state")
	}

	token, err := o.Config.Exchange(ctx, code)
	if err != nil {
		return OAuth2Info{}, fmt.Errorf("code exchange failed: %s", err.Error())
	}

	url := fmt.Sprintf(googleUserInfoUrl, token.AccessToken)
	response, err := o.Client.Get(url)
	if err != nil {
		return OAuth2Info{}, fmt.Errorf("failed getting user info: %s", err.Error())
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return OAuth2Info{}, fmt.Errorf("failed reading response body: %s", err.Error())
	}
	var u OAuth2Info
	if err := json.Unmarshal(contents, &u); err != nil {
		return OAuth2Info{}, fmt.Errorf("cannot read response from google: %s", err.Error())
	}

	return u, nil
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
