# go-jwt-oauth2
Provides mechanisms for JWT authorization handling and oauth2 sign in. 
`examples` directory contains examples for each implementation separately, and both combined as well. 

**This `README` file has instructions for running the combination of both `JWT` and `oauth2`.**

### How to run

Run a dummy redis docker container at `localhost:6379`, by typing:
```shell
make redis-start
```
This will be useful as an in-memory storage for your JWT tokens. For a different redis location, 
use environment variable `REDIS_DSN`. 

Make sure you have google credentials for your application. 
`GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` will be needed as environment variables.

You can run the application by typing:
```shell
GOOGLE_CLIENT_ID=xxx GOOGLE_CLIENT_SECRET=xxx go run examples/both/main.go
```

## It works!

### Obtain access + refresh tokens
#### Via google ID
Visit `http://localhost:8080`. Click "Google Log In" link. It will redirect you to google sign
in page to enter your google credentials. Once you put them correctly, you will receive a response
which looks like this:
```shell
{
	"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3NfdXVpZCI6IjQ5NzViMWQ0LWRlZjUtNDNlMC1iNzQzLTdlNTIzZWY0YTA5NyIsImF1dGhvcml6ZWQiOnRydWUsImV4cCI6MTY0NzU0MjY2NCwidXNlcl9pZCI6IjE0ZGU0MTAzLTgzZmItNDEwYS1hZmRkLWQxYzFhZGZjYmE3YiJ9.PyE8HbDumcNJMOleb2S8pfyqN94niDLl3jqjPLnq5iE",
	"refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NDgxNDY1NjQsInJlZnJlc2hfdXVpZCI6IjQ5NzViMWQ0LWRlZjUtNDNlMC1iNzQzLTdlNTIzZWY0YTA5NysrMTRkZTQxMDMtODNmYi00MTBhLWFmZGQtZDFjMWFkZmNiYTdiIiwidXNlcl9pZCI6IjE0ZGU0MTAzLTgzZmItNDEwYS1hZmRkLWQxYzFhZGZjYmE3YiJ9.qdhZDYIFKxWelvAIH1CN3gFbC8QagPs1M9zcV9mrkU0"
}
```
#### Via standard login
Do a POST request to the `/login` endpoint, with username `username` and password `password`.
```shell
curl -XPOST http://localhost:8080/login -H 'Content-Type: application/json' -d '{"username":"username", "password":"password"}'
```

You will again receive a response with an `access_token` and a `refresh_token` same as the above.


### You are in.
Congrats, you have now access to the application! You can use the `access_token` in your 
authorization header to perform requests to the application, or the `refresh_token` to refresh
both of your tokens.

### Authenticated request
You can now make requests to the application like this:
```shell
curl -XPOST http://localhost:8080/task \
  -H 'Authorization: Bearer {your.access.token}' \
  -H 'Content-Type: application/json' \
  -d '{"name": "whatever"}'
```
of course by replacing `{your.access.token}` with your actual access token you received above.

### Refresh tokens
You can refresh your tokens by making a POST request to the `/refresh` endpoint:
```shell
curl -XPOST http://localhost:8080/refresh \
  -H 'Content-Type: application/json' \
  -d '{
  "refresh_token": {your.refresh.token}
}'
```
of course by replacing `{your.refresh.token}` with your actual refresh token you received above.

### Unauthorized when?
Of course, if an invalid token is used, or an `access_token` is expired, a `401 Unauthorized`
response will be returned.

### Extendable
- Can support other oauth2 implementations in future
- JWT temporary storage other than redis, can be used. Check `Keeper` interface in `jwt` package.

### References
_JWT implementation inspired from [here](https://learn.vonage.com/blog/2020/03/13/using-jwt-for-authentication-in-a-golang-application-dr/)._
