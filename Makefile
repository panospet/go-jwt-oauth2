.PHONY: redis-start
redis-start:
	docker run --rm --name jwt-redis -d -p 6379:6379 redis

.PHONY: redis-stop
redis-stop:
	docker stop jwt-redis