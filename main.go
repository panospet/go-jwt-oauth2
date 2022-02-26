package main

import (
	"github.com/go-redis/redis/v7"
	"github.com/panospet/go-jwt-oauth2/api"
	"github.com/panospet/go-jwt-oauth2/jwt"
	"github.com/panospet/go-jwt-oauth2/jwt/authkeep"
	"github.com/panospet/go-jwt-oauth2/util"
)

func main() {
	dsn := util.EnvOrDefault("REDIS_DSN", "localhost:6379")
	redisClient := redis.NewClient(&redis.Options{
		Addr: dsn,
	})
	_, err := redisClient.Ping().Result()
	if err != nil {
		panic(err)
	}
	authKeeper := authkeep.NewRedisKeeper(redisClient)
	accessSecret := util.EnvOrDefault("ACCESS_SECRET", "access-secret")
	refreshSecret := util.EnvOrDefault("REFRESH_SECRET", "refresh-secret")
	jwtMan := jwt.NewJwtManager(accessSecret, refreshSecret, authKeeper)
	app := api.NewApi(jwtMan)
	panic(app.Run())
}
