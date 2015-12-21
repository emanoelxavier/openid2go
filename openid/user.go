package openid

import (
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

type User struct {
	Issuer string
	Id     string
	Claims map[string]interface{}
}

func newUser(t *jwt.Token) (*User, error) {
	if t == nil {
		return nil, &ValidationError{Code: ValidationErrorIdTokenEmpty, Message: "The token provided to created a user was nil.", HTTPStatus: http.StatusUnauthorized}
	}

	iss := getIssuer(t).(string)

	if iss == "" {
		return nil, &ValidationError{Code: ValidationErrorInvalidIssuer, Message: "The token provided to created a user did not contain a valid 'iss' claim", HTTPStatus: http.StatusInternalServerError}
	}

	sub := getSubject(t).(string)

	if sub == "" {
		return nil, &ValidationError{Code: ValidationErrorInvalidSubject, Message: "The token provided to created a user did not contain a valid 'sub' claim.", HTTPStatus: http.StatusInternalServerError}

	}

	u := new(User)
	u.Issuer = iss
	u.Id = sub
	u.Claims = t.Claims
	return u, nil
}
