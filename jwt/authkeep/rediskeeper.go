package authkeep

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisKeeper struct {
	RedisClient *redis.Client
}

func NewRedisKeeper(redisClient *redis.Client) *RedisKeeper {
	return &RedisKeeper{RedisClient: redisClient}
}

func (a *RedisKeeper) AddAuth(
	ctx context.Context,
	userid string,
	tokens JwtTokens,
) error {
	at := time.Unix(tokens.AccessToken.Expires, 0) //converting Unix to UTC(to Time object)
	rt := time.Unix(tokens.RefreshToken.Expires, 0)
	now := time.Now()

	errAccess := a.RedisClient.Set(
		ctx,
		tokens.AccessToken.Uuid,
		userid,
		at.Sub(now),
	).Err()
	if errAccess != nil {
		return errAccess
	}
	errRefresh := a.RedisClient.Set(
		ctx,
		tokens.RefreshToken.Uuid,
		userid,
		rt.Sub(now),
	).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}

func (a *RedisKeeper) FetchAuth(
	ctx context.Context,
	access Access,
) (string, error) {
	userId, err := a.RedisClient.Get(ctx, access.Uuid).Result()
	if err != nil {
		return "", fmt.Errorf("cannot get accessDetails from redis: %s", err)
	}
	if access.UserId != userId {
		return "", fmt.Errorf("access.UserId != userId, %s != %s", access.UserId, userId)
	}
	return userId, nil
}

func (a *RedisKeeper) DeleteAuthByUuid(
	ctx context.Context,
	uuid string,
) (int64, error) {
	deleted, err := a.RedisClient.Del(ctx, uuid).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

func (a *RedisKeeper) DeleteByAccess(
	ctx context.Context,
	access Access,
) error {
	//get the refresh uuid
	refreshUuid := fmt.Sprintf("%s++%s", access.Uuid, access.UserId)
	//delete access token
	deletedAt, err := a.RedisClient.Del(ctx, access.Uuid).Result()
	if err != nil {
		return err
	}
	//delete refresh token
	deletedRt, err := a.RedisClient.Del(ctx, refreshUuid).Result()
	if err != nil {
		return err
	}
	//When the record is deleted, the return value is 1
	if deletedAt != 1 || deletedRt != 1 {
		return errors.New("something went wrong")
	}
	return nil
}
