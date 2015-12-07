package openid

import (
	"net/http"
	"strings"
)

type GetIdToken func(r http.Request) (t string, err error)

func GetIdTokenAuthorizationHeader(r http.Request) (t string, err error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return h, &ValidationError{Code: ValidationErrorAuthorizationHeaderNotFound, Message: "The 'Authorization' header was not found or was empty.", HTTPStatus: http.StatusBadRequest}
	}

	p := strings.Split(h, " ")

	if len(p) != 2 {
		return h, &ValidationError{Code: ValidationErrorAuthorizationHeaderWrongFormat, Message: "The 'Authorization' header did not have the correct format.", HTTPStatus: http.StatusBadRequest}
	}

	if p[0] != "Bearer" {
		return h, &ValidationError{Code: ValidationErrorAuthorizationHeaderWrongSchemeName, Message: "The 'Authorization' header scheme name was not 'Bearer'", HTTPStatus: http.StatusBadRequest}
	}

	return p[1], nil
}
