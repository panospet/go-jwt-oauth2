package jwt

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"

	"github.com/panospet/go-jwt-oauth2/jwt/authkeep"
)

type JwtManager struct {
	AccessSecret  string
	RefreshSecret string
	Keeper        authkeep.Keeper
}

func NewJwtManager(accessSecret string,
	refreshSecret string,
	keeper authkeep.Keeper,
) *JwtManager {
	return &JwtManager{
		AccessSecret:  accessSecret,
		RefreshSecret: refreshSecret,
		Keeper:        keeper,
	}
}

func (m *JwtManager) Authenticate(tokenStr string) error {
	token, err := m.verifyToken(tokenStr)
	if err != nil {
		return err
	}
	access, err := m.extractAccess(token)
	if err != nil {
		return err
	}
	_, err = m.Keeper.FetchAuth(access)
	if err != nil {
		return err
	}
	return nil
}

func (m *JwtManager) DeAuthenticate(tokenStr string) error {
	token, err := m.verifyToken(tokenStr)
	if err != nil {
		return err
	}
	access, err := m.extractAccess(token)
	if err != nil {
		return err
	}
	return m.Keeper.DeleteByAccess(access)
}

func (m *JwtManager) verifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.AccessSecret), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (m *JwtManager) createTokens(userid string) (authkeep.JwtTokens, error) {
	td := authkeep.JwtTokens{}
	td.AccessToken.Expires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessToken.Uuid = uuid.New().String()

	td.RefreshToken.Expires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshToken.Uuid = td.AccessToken.Uuid + "++" + userid

	var err error
	accessTokenClaims := jwt.MapClaims{}
	accessTokenClaims["authorized"] = true
	accessTokenClaims["access_uuid"] = td.AccessToken.Uuid
	accessTokenClaims["user_id"] = userid
	accessTokenClaims["exp"] = td.AccessToken.Expires
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	td.AccessToken.Value, err = accessToken.SignedString([]byte(m.AccessSecret))
	if err != nil {
		return authkeep.JwtTokens{}, err
	}

	refreshTokenClaims := jwt.MapClaims{}
	refreshTokenClaims["refresh_uuid"] = td.RefreshToken.Uuid
	refreshTokenClaims["user_id"] = userid
	refreshTokenClaims["exp"] = td.RefreshToken.Expires
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	td.RefreshToken.Value, err = refreshToken.SignedString([]byte(m.RefreshSecret))
	if err != nil {
		return authkeep.JwtTokens{}, err
	}
	return td, nil
}

func (m *JwtManager) CreateAndStoreTokens(userId string) (authkeep.JwtTokens, error) {
	tokens, err := m.createTokens(userId)
	if err != nil {
		return authkeep.JwtTokens{}, fmt.Errorf("cannot create token: %s", err)
	}

	if err := m.Keeper.AddAuth(userId, tokens); err != nil {
		return authkeep.JwtTokens{}, err
	}

	return tokens, nil
}

func (m *JwtManager) extractAccess(token *jwt.Token) (authkeep.Access, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return authkeep.Access{}, fmt.Errorf("cannot extract claims from token")
	}

	if !token.Valid {
		return authkeep.Access{}, fmt.Errorf("invalid token")
	}

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

func (m *JwtManager) RefreshTokens(refreshToken string) (authkeep.JwtTokens, error) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.RefreshSecret), nil
	})

	if err != nil {
		return authkeep.JwtTokens{}, fmt.Errorf("invalid (expired?) token: %s", err)
	}

	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return authkeep.JwtTokens{}, fmt.Errorf("invalid token: %s", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		refreshUuid, ok := claims["refresh_uuid"].(string)
		if !ok {
			return authkeep.JwtTokens{}, fmt.Errorf("cannot find refresh uuid: %s", err)
		}
		userId := claims["user_id"].(string)
		deleted, delErr := m.Keeper.DeleteAuthByUuid(refreshUuid)
		if delErr != nil || deleted == 0 {
			return authkeep.JwtTokens{}, fmt.Errorf("could not remove auth entry: %s", err)
		}
		return m.CreateAndStoreTokens(userId)
	}

	return authkeep.JwtTokens{}, fmt.Errorf("cannot get claims OR invalid token: %s", err)
}
