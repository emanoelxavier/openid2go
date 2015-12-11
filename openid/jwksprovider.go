package openid

import (
	"fmt"
	"net/http"

	"github.com/square/go-jose"
)

type jwksProvider interface {
	getJwks(string) (*configuration, error)
}

type httpJwksProvider struct {
	jwksGetter  httpGetFunc
	jwksDecoder decodeResponseFunc
}

func (httpProv httpJwksProvider) getJwks(url string) (jose.JsonWebKeySet, error) {

	var jwks jose.JsonWebKeySet
	resp, err := httpProv.jwksGetter(url)

	if err != nil {
		return jwks, &ValidationError{Code: ValidationErrorGetJwksFailure, Message: fmt.Sprintf("Failure while contacting the jwk endpoint %v.", url), Err: err, HTTPStatus: http.StatusUnauthorized}
	}

	defer resp.Body.Close()

	if err := httpProv.jwksDecoder(resp.Body, &jwks); err != nil { //json.NewDecoder(resp.Body).Decode(&jwkSet); err != nil {
		return jwks, &ValidationError{Code: ValidationErrorDecodeJwksFailure, Message: fmt.Sprintf("Failure while decoding the jwk retrieved from the  endpoint %v.", url), Err: err, HTTPStatus: http.StatusUnauthorized}
	}

	return jwks, nil
}
