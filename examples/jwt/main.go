package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-redis/redis/v7"

	"github.com/panospet/go-jwt-oauth2/jwt"
	"github.com/panospet/go-jwt-oauth2/jwt/authkeep"
)

var JwtManager *jwt.JwtManager

func main() {
	redisAddr := os.Getenv("REDIS_DSN")
	if len(redisAddr) == 0 {
		redisAddr = "localhost:6379"
	}
	redisClient := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	keeper := authkeep.NewRedisKeeper(redisClient)
	JwtManager = jwt.NewJwtManager("access-secret", "refresh-secret", keeper)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// no middleware group
	r.Group(
		func(r chi.Router) {
			r.Post("/login", Login)
			r.Post("/refresh", Refresh)
		},
	)

	// middleware group
	r.Group(
		func(r chi.Router) {
			r.Use(JwtMiddleware)
			r.Post("/logout", Logout)
			r.Post("/task", DoTask)
		},
	)

	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "5555"
	}
	log.Printf("listening on %s\n", port)
	panic(http.ListenAndServe(fmt.Sprintf("0.0.0.0:%s", port), r))
}

func JwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := ExtractTokenFromRequest(r)
		if err := JwtManager.Authenticate(tokenStr); err != nil {
			log.Println(err)
			JSON(w, r, http.StatusUnauthorized, Respond("unauthorized"))
			return
		}
		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func Login(w http.ResponseWriter, r *http.Request) {
	var u User
	bod, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		JSON(w, r, http.StatusBadRequest, Respond("Invalid json provided"))
		return
	}

	if err := json.Unmarshal(bod, &u); err != nil {
		JSON(w, r, http.StatusBadRequest, Respond("Invalid json provided"))
		return
	}

	// assuming we search in database and find the user
	if exampleUser.Username != u.Username || exampleUser.Password != u.Password {
		JSON(w, r, http.StatusBadRequest, Respond("Please provide valid login details"))
		return
	}

	ts, err := JwtManager.CreateAndStoreTokens(exampleUser.ID)
	if err != nil {
		JSON(w, r, http.StatusInternalServerError, Respond("cannot login"))
	}
	tokens := map[string]string{
		"access_token":  ts.AccessToken.Value,
		"refresh_token": ts.RefreshToken.Value,
	}
	JSON(w, r, http.StatusOK, tokens)
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	mapToken := map[string]string{}

	bod, err := io.ReadAll(r.Body)
	if err != nil {
		JSON(w, r, http.StatusBadRequest, Respond("bad json"))
		return
	}
	if err := json.Unmarshal(bod, &mapToken); err != nil {
		JSON(w, r, http.StatusBadRequest, Respond("bad json"))
		return
	}

	refreshToken := mapToken["refresh_token"]
	ts, err := JwtManager.RefreshTokens(refreshToken)
	if err != nil {
		JSON(w, r, http.StatusUnauthorized, Respond("refresh expired"))
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
		JSON(w, r, http.StatusBadRequest, Respond("invalid json"))
		return
	}
	defer r.Body.Close()
	if err := json.Unmarshal(b, &task); err != nil {
		JSON(w, r, http.StatusBadRequest, Respond("invalid json"))
		return
	}
	JSON(w, r, http.StatusCreated, Respond(fmt.Sprintf("task %s done", task.Name)))
}

func Logout(w http.ResponseWriter, r *http.Request) {
	tokenStr := ExtractTokenFromRequest(r)
	if err := JwtManager.DeAuthenticate(tokenStr); err != nil {
		JSON(w, r, http.StatusUnauthorized, Respond("unauthorized"))
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

type Response struct {
	Message string `json:"message"`
}

func Respond(msg string) Response {
	return Response{Message: msg}
}

func JSON(w http.ResponseWriter, r *http.Request, statusCode int, content interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(content); err != nil {
		log.Println("failed to marshal ErrorResp:", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

var exampleUser = User{
	ID:       "c9c65e83-8a93-4b8c-9be0-50914727c029",
	Username: "username",
	Password: "password",
}
