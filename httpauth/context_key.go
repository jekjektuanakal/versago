package httpauth

type CtxKey string

const (
	CtxKeySubject  CtxKey = "subject"
	CtxKeyJWT      CtxKey = "token"
	CtxKeyDIDClaim CtxKey = "did"
)
