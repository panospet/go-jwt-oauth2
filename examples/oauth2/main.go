package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"log"
	"net/http"
	"os"
	"time"

	myoauth "github.com/panospet/go-jwt-oauth2/oauth2"
)

var (
	googleOauth2Config *oauth2.Config
	googleOauthHandler *myoauth.GoogleOAuthHandler
)

func init() {
	googleOauth2Config = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/callback",
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
}

func main() {
	googleOauthHandler = myoauth.NewGoogleOAuthHandler(googleOauth2Config, &http.Client{
		Timeout: 30 * time.Second,
	})

	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", googleLogin)
	http.HandleFunc("/callback", googleCallbackHandler)

	log.Println("serving...")
	log.Fatalln(http.ListenAndServe(":8080", nil))
}

func googleLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, googleOauthHandler.GetRedirectUrlToSignIn(), http.StatusTemporaryRedirect)
}

func googleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	code := r.FormValue("code")
	userInfo, err := googleOauthHandler.GetUserInfo(r.Context(), state, code)
	if err != nil {
		JSON(w, r, http.StatusUnauthorized, Respond("unauthorized"))
		return
	}

	JSON(w, r, http.StatusOK, userInfo)
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	var htmlIndex = `<html>
<body>
	<a href="/login">Google Log In</a>
</body>
</html>`

	fmt.Fprintf(w, htmlIndex)
}

func JSON(w http.ResponseWriter, r *http.Request, statusCode int, content interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(content); err != nil {
		log.Println("failed to marshal ErrorResp:", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

type Response struct {
	Message string `json:"message"`
}

func Respond(msg string) Response {
	return Response{Message: msg}
}
