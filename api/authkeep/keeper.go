package authkeep

type Keeper interface {
	CreateAuth(userid string, auth Auth) error
	FetchAuth(access Access) (string, error)
	DeleteAuthByUuid(uuid string) (int64, error)
	DeleteByAccess(access Access) error
}
