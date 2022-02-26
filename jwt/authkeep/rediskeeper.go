package authkeep

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v7"
)

type RedisKeeper struct {
	RedisClient *redis.Client
}

func NewRedisKeeper(redisClient *redis.Client) *RedisKeeper {
	return &RedisKeeper{RedisClient: redisClient}
}

func (a *RedisKeeper) AddAuth(userid string, tokens JwtTokens) error {
	at := time.Unix(tokens.AccessToken.Expires, 0) //converting Unix to UTC(to Time object)
	rt := time.Unix(tokens.RefreshToken.Expires, 0)
	now := time.Now()

	errAccess := a.RedisClient.Set(tokens.AccessToken.Uuid, userid, at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	errRefresh := a.RedisClient.Set(tokens.RefreshToken.Uuid, userid, rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}

func (a *RedisKeeper) FetchAuth(access Access) (string, error) {
	userId, err := a.RedisClient.Get(access.Uuid).Result()
	if err != nil {
		return "", fmt.Errorf("cannot get accessDetails from redis: %s", err)
	}
	if access.UserId != userId {
		return "", fmt.Errorf("access.UserId != userId, %s != %s", access.UserId, userId)
	}
	return userId, nil
}

func (a *RedisKeeper) DeleteAuthByUuid(uuid string) (int64, error) {
	deleted, err := a.RedisClient.Del(uuid).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

func (a *RedisKeeper) DeleteByAccess(access Access) error {
	//get the refresh uuid
	refreshUuid := fmt.Sprintf("%s++%s", access.Uuid, access.UserId)
	//delete access token
	deletedAt, err := a.RedisClient.Del(access.Uuid).Result()
	if err != nil {
		return err
	}
	//delete refresh token
	deletedRt, err := a.RedisClient.Del(refreshUuid).Result()
	if err != nil {
		return err
	}
	//When the record is deleted, the return value is 1
	if deletedAt != 1 || deletedRt != 1 {
		return errors.New("something went wrong")
	}
	return nil
}
