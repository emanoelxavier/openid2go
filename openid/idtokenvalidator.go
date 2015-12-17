package openid

import "github.com/dgrijalva/jwt-go"

type jwtTokenValidator interface {
	validate(token string) (t *jwt.Token, err error)
}

type idTokenValidator struct {
}
