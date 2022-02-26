// Based on the guide below:
// https://learn.vonage.com/blog/2020/03/13/using-jwt-for-authentication-in-a-golang-application-dr/
// https://github.com/victorsteven/jwt-best-practices/blob/master/main.go

package api

import (
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/panospet/go-jwt-oauth2/jwt"
	"github.com/panospet/go-jwt-oauth2/user"
	"github.com/panospet/go-jwt-oauth2/util"
	"io"
	"log"
	"net/http"
	"strings"
)

type Api struct {
	JwtManager *jwt.JwtManager
}

func NewApi(jwtManager *jwt.JwtManager) *Api {
	return &Api{
		JwtManager: jwtManager,
	}
}

func (a *Api) Run() error {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// no middleware group
	r.Group(
		func(r chi.Router) {
			r.Post("/login", a.Login)
			r.Post("/refresh", a.Refresh)
		},
	)

	// middleware group
	r.Group(
		func(r chi.Router) {
			r.Use(a.JwtMiddleware)
			r.Post("/logout", a.Logout)
			r.Post("/task", DoTask)
		},
	)

	port := util.EnvOrDefault("PORT", ":5555")
	log.Printf("listening on %s\n", port)
	return http.ListenAndServe(port, r)
}

var exampleUuid = "c9c65e83-8a93-4b8c-9be0-50914727c029"
var user1 = user.User{
	ID:       exampleUuid,
	Username: "username",
	Password: "password",
}

type Response struct {
	Message string `json:"message"`
}

func Resp(msg string) Response {
	return Response{Message: msg}
}

func (a *Api) JwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := ExtractTokenFromRequest(r)
		if err := a.JwtManager.Authenticate(tokenStr); err != nil {
			log.Println(err)
			JSON(w, r, http.StatusUnauthorized, Resp("unauthorized"))
			return
		}
		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}

func (a *Api) Login(w http.ResponseWriter, r *http.Request) {
	var u user.User
	bod, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		JSON(w, r, http.StatusBadRequest, Resp("Invalid json provided"))
		return
	}

	if err := json.Unmarshal(bod, &u); err != nil {
		JSON(w, r, http.StatusBadRequest, Resp("Invalid json provided"))
		return
	}

	// todo ask user repository
	if user1.Username != u.Username || user1.Password != u.Password {
		JSON(w, r, http.StatusBadRequest, Resp("Please provide valid login details"))
		return
	}

	ts, err := a.JwtManager.CreateAndStoreTokens(user1.ID)
	if err != nil {
		JSON(w, r, http.StatusInternalServerError, Resp("cannot login"))
	}
	tokens := map[string]string{
		"access_token":  ts.AccessToken.Value,
		"refresh_token": ts.RefreshToken.Value,
	}
	JSON(w, r, http.StatusOK, tokens)
}

func (a *Api) Refresh(w http.ResponseWriter, r *http.Request) {
	mapToken := map[string]string{}

	bod, err := io.ReadAll(r.Body)
	if err != nil {
		JSON(w, r, http.StatusBadRequest, Resp("bad json"))
		return
	}
	if err := json.Unmarshal(bod, &mapToken); err != nil {
		JSON(w, r, http.StatusBadRequest, Resp("bad json"))
		return
	}

	refreshToken := mapToken["refresh_token"]
	ts, err := a.JwtManager.RefreshTokens(refreshToken)
	if err != nil {
		JSON(w, r, http.StatusUnauthorized, Resp("refresh expired"))
		return
	}
	tokens := map[string]string{
		"access_token":  ts.AccessToken.Value,
		"refresh_token": ts.RefreshToken.Value,
	}
	JSON(w, r, http.StatusCreated, tokens)
}

type Task struct {
	Name string `json:"name"`
}

func DoTask(w http.ResponseWriter, r *http.Request) {
	var task Task
	b, err := io.ReadAll(r.Body)
	if err != nil {
		JSON(w, r, http.StatusBadRequest, Resp("invalid json"))
		return
	}
	defer r.Body.Close()
	if err := json.Unmarshal(b, &task); err != nil {
		JSON(w, r, http.StatusBadRequest, Resp("invalid json"))
		return
	}
	JSON(w, r, http.StatusCreated, Resp(fmt.Sprintf("task %s done", task.Name)))
}

func (a *Api) Logout(w http.ResponseWriter, r *http.Request) {
	tokenStr := ExtractTokenFromRequest(r)
	if err := a.JwtManager.DeAuthenticate(tokenStr); err != nil {
		JSON(w, r, http.StatusUnauthorized, Resp("unauthorized"))
		return
	}
	JSON(w, r, http.StatusOK, nil)
}

func ExtractTokenFromRequest(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func JSON(w http.ResponseWriter, r *http.Request, statusCode int, content interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(content); err != nil {
		log.Println("failed to marshal ErrorResp:", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}
