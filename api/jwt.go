package api

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/panospet/go-jwt-oauth2/api/authkeep"
	"github.com/panospet/go-jwt-oauth2/utl"
	"log"
	"net/http"
	"strings"
	"time"
)

var accessSecret = utl.EnvOrDefault("ACCESS_SECRET", "access-secret")
var refreshSecret = utl.EnvOrDefault("REFRESH_SECRET", "refresh-secret")

func (a *Api) JwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadata, err := ExtractAccess(r)
		if err != nil {
			JSON(w, r, http.StatusBadRequest, Resp("unauthorized"))
			return
		}
		_, err = a.AuthKeeper.FetchAuth(metadata)
		if err != nil {
			log.Println("")
			JSON(w, r, http.StatusUnauthorized, Resp("unauthorized"))
			return
		}

		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}

func ExtractAccess(r *http.Request) (authkeep.Access, error) {
	token, err := VerifyToken(r)
	if err != nil {
		return authkeep.Access{}, fmt.Errorf("token could not be verified")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		if !ok {
			return authkeep.Access{}, fmt.Errorf("access_uuid not found in claims")
		}
		uId, ok := claims["user_id"].(string)
		if !ok {
			return authkeep.Access{}, fmt.Errorf("user_id not found in claims")
		}
		acc := authkeep.Access{
			Uuid:   accessUuid,
			UserId: uId,
		}
		return acc, nil
	}
	return authkeep.Access{}, err
}
func ExtractTokenFromRequest(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtractTokenFromRequest(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(accessSecret), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func TokenValid(r *http.Request) error {
	token, err := VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok || !token.Valid {
		return err
	}
	return nil
}

func CreateToken(userid string) (authkeep.Auth, error) {
	td := authkeep.Auth{}
	td.AccessToken.Expires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessToken.Uuid = uuid.New().String()

	td.RefreshToken.Expires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshToken.Uuid = td.AccessToken.Uuid + "++" + userid

	var err error
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessToken.Uuid
	atClaims["user_id"] = userid
	atClaims["exp"] = td.AccessToken.Expires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken.Value, err = at.SignedString([]byte(accessSecret))
	if err != nil {
		return authkeep.Auth{}, err
	}
	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshToken.Uuid
	rtClaims["user_id"] = userid
	rtClaims["exp"] = td.RefreshToken.Expires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken.Value, err = rt.SignedString([]byte(refreshSecret))
	if err != nil {
		return authkeep.Auth{}, err
	}
	return td, nil
}
