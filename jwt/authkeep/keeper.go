package authkeep

type Keeper interface {
	AddAuth(userid string, auth JwtTokens) error
	FetchAuth(access Access) (string, error)
	DeleteAuthByUuid(uuid string) (int64, error)
	DeleteByAccess(access Access) error
}

type Access struct {
	Uuid   string
	UserId string
}

type Token struct {
	Value   string
	Uuid    string
	Expires int64
}

type JwtTokens struct {
	AccessToken  Token
	RefreshToken Token
}
