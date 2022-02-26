package main

import (
	"github.com/go-redis/redis/v7"
	"github.com/panospet/go-jwt-oauth2/api"
	"github.com/panospet/go-jwt-oauth2/api/authkeep"
	"github.com/panospet/go-jwt-oauth2/utl"
)

func main() {
	dsn := utl.EnvOrDefault("REDIS_DSN", "localhost:6379")
	redisClient := redis.NewClient(&redis.Options{
		Addr: dsn,
	})
	_, err := redisClient.Ping().Result()
	if err != nil {
		panic(err)
	}
	authKeeper := authkeep.NewRedisKeeper(redisClient)
	app := api.NewApi(authKeeper)
	panic(app.Run())
}
