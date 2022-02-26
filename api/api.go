// Based on the guide below:
// https://learn.vonage.com/blog/2020/03/13/using-jwt-for-authentication-in-a-golang-application-dr/
// https://github.com/victorsteven/jwt-best-practices/blob/master/main.go

package api

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/panospet/go-jwt-oauth2/api/authkeep"
	user2 "github.com/panospet/go-jwt-oauth2/user"
	"github.com/panospet/go-jwt-oauth2/utl"
	"io"
	"log"
	"net/http"
)

type Api struct {
	AuthKeeper authkeep.Keeper
}

func NewApi(authKeeper authkeep.Keeper) *Api {
	return &Api{
		AuthKeeper: authKeeper,
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
			r.Post("/logout", a.Logout)
		},
	)

	// middleware group
	r.Group(
		func(r chi.Router) {
			r.Use(a.JwtMiddleware)

			r.Post("/task", DoTask)
		},
	)

	port := utl.EnvOrDefault("PORT", ":5555")
	log.Printf("listening on %s\n", port)
	return http.ListenAndServe(port, r)
}

var exampleUuid = "c9c65e83-8a93-4b8c-9be0-50914727c029"
var user = user2.User{
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

func (a *Api) Login(w http.ResponseWriter, r *http.Request) {
	var u user2.User
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

	// compare the user from the request, with the one we defined:
	// todo ask user repository
	if user.Username != u.Username || user.Password != u.Password {
		JSON(w, r, http.StatusBadRequest, Resp("Please provide valid login details"))
		return
	}

	ts, err := CreateToken(user.ID)
	if err != nil {
		log.Println(err)
		JSON(w, r, http.StatusInternalServerError, Resp("cannot create token"))
		return
	}

	if err := a.AuthKeeper.CreateAuth(user.ID, ts); err != nil {
		log.Println(err)
		JSON(w, r, http.StatusInternalServerError, Resp("create auth err"))
		return
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

	//verify the token
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(refreshSecret), nil
	})
	//if there is an error, the token must have expired
	if err != nil {
		log.Println(err)
		JSON(w, r, http.StatusUnauthorized, Resp("invalid token"))
		return
	}
	//is token valid?
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		JSON(w, r, http.StatusUnauthorized, Resp("invalid token"))
		return
	}
	//Since token is valid, get the uuid:
	claims, ok := token.Claims.(jwt.MapClaims) //the token claims should conform to MapClaims
	if ok && token.Valid {
		refreshUuid, ok := claims["refresh_uuid"].(string) //convert the interface to string
		if !ok {
			JSON(w, r, http.StatusUnprocessableEntity, Resp(err.Error()))
			return
		}
		userId := claims["user_id"].(string)
		//Delete the previous Refresh Token
		deleted, delErr := a.AuthKeeper.DeleteAuthByUuid(refreshUuid)
		if delErr != nil || deleted == 0 { //if any goes wrong
			JSON(w, r, http.StatusUnauthorized, Resp("unauthorized"))
			return
		}
		//Create new pairs of refresh and access tokens
		ts, err := CreateToken(userId)
		if err != nil {
			JSON(w, r, http.StatusForbidden, err.Error())
			return
		}
		//save the tokens metadata to redis
		if err := a.AuthKeeper.CreateAuth(userId, ts); err != nil {
			JSON(w, r, http.StatusForbidden, Resp(err.Error()))
			return
		}
		tokens := map[string]string{
			"access_token":  ts.AccessToken.Value,
			"refresh_token": ts.RefreshToken.Value,
		}
		JSON(w, r, http.StatusCreated, tokens)
	} else {
		JSON(w, r, http.StatusUnauthorized, Resp("refresh expired"))
	}
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

	if err := json.Unmarshal(b, &task); err != nil {
		JSON(w, r, http.StatusBadRequest, Resp("invalid json"))
		return
	}

	JSON(w, r, http.StatusCreated, Resp(fmt.Sprintf("task %s done", task.Name)))
}

func (a *Api) Logout(w http.ResponseWriter, r *http.Request) {
	metadata, err := ExtractAccess(r)
	if err != nil {
		JSON(w, r, http.StatusUnauthorized, Resp("unauthorized"))
		return
	}
	delErr := a.AuthKeeper.DeleteByAccess(metadata)
	if delErr != nil {
		JSON(w, r, http.StatusUnauthorized, delErr.Error())
		return
	}
	JSON(w, r, http.StatusOK, nil)
}

func JSON(w http.ResponseWriter, r *http.Request, statusCode int, content interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(content); err != nil {
		log.Println("failed to marshal ErrorResp:", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}
