package httpauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/rs/zerolog/log"

	"github.com/jekjektuanakal/versago/errkind"
	"github.com/jekjektuanakal/versago/httpx"
)

type JWTAuthenticator struct {
	mutex        sync.RWMutex
	url          url.URL
	updatePeriod time.Duration
	jwks         jwk.Set
	ctx          context.Context
	cancel       context.CancelFunc
}

func NewJWTAuthenticatorFromJWKSURL(jwksURL url.URL, updatePeriod time.Duration) (*JWTAuthenticator, error) {
	jwks, err := getJwks(jwksURL)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	auth := &JWTAuthenticator{url: jwksURL, updatePeriod: updatePeriod, jwks: jwks, ctx: ctx, cancel: cancel}

	go auth.updateJWKS()

	return auth, nil
}

func (authn *JWTAuthenticator) Stop() {
	authn.cancel()
}

func (authn *JWTAuthenticator) parseJwtToken(r *http.Request) (jwt.Token, error) {
	rawToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	if rawToken == "" {
		return nil, fmt.Errorf("token is empty: %w", errkind.ErrUnauthorized)
	}

	authn.mutex.RLock()
	token, err := jwt.Parse([]byte(rawToken), jwt.WithKeySet(authn.jwks))
	authn.mutex.RUnlock()

	if err != nil {
		return nil, fmt.Errorf("parse token failed:%w : %w", errkind.ErrUnauthorized, err)
	}

	return token, nil
}

func (authn *JWTAuthenticator) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := authn.parseJwtToken(r)
		if err != nil {
			httpx.WriteResponse(w, struct{}{}, err)
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), CtxKeyJWT, token)))
	})
}

func (authn *JWTAuthenticator) updateJWKS() {
	for {
		select {
		case <-authn.ctx.Done():
			return
		case <-time.After(authn.updatePeriod):
			jwks, err := getJwks(authn.url)
			if err != nil {
				log.Warn().Err(err).Msg("update JWKS failed")
				continue
			}

			authn.mutex.Lock()
			authn.jwks = jwks
			authn.mutex.Unlock()
		}
	}
}

func getJwks(jwksURL url.URL) (jwk.Set, error) {
	response, err := http.DefaultClient.Get(jwksURL.String())
	if err != nil {
		return nil, fmt.Errorf("get JWKS from url '%s' failed: %w", jwksURL.String(), err)
	}

	defer func() {
		err = response.Body.Close()
		if err != nil {
			log.Error().Err(err).Msg("close JWKS response body failed")
		}
	}()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read JWKS response from url '%s' failed: %w", jwksURL.String(), err)
	}

	jwks, err := jwk.Parse(responseBody)
	if err != nil {
		return nil, fmt.Errorf("parse JWKS from url '%s' failed: %w", jwksURL.String(), err)
	}

	return jwks, nil
}

func GetDIDFromContext(ctx context.Context) (string, error) {
	token, tokenFound := ctx.Value(CtxKeyJWT).(jwt.Token)
	if !tokenFound {
		return "", fmt.Errorf("get JWT from context failed")
	}

	did, didFound := token.PrivateClaims()["did"].(string)
	if !didFound || did == "" {
		return "", fmt.Errorf("DID not found in JWT token")
	}

	return did, nil
}
