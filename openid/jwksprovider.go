package openid

import (
	"fmt"
	"io"
	"net/http"

	jose "gopkg.in/square/go-jose.v2"
)

type jwksGetter interface {
	get(r *http.Request, url string) (jose.JSONWebKeySet, error)
}

type jwksDecoder interface {
	decode(io.Reader) (jose.JSONWebKeySet, error)
}

type httpJwksProvider struct {
	getter  httpGetter
	decoder jwksDecoder
}

func newHTTPJwksProvider(gf HTTPGetFunc, d jwksDecoder) *httpJwksProvider {
	return &httpJwksProvider{gf, d}
}

func (httpProv *httpJwksProvider) get(r *http.Request, url string) (jose.JSONWebKeySet, error) {

	var jwks jose.JSONWebKeySet
	resp, err := httpProv.getter.get(r, url)

	if err != nil {
		return jwks, &ValidationError{
			Code:       ValidationErrorGetJwksFailure,
			Message:    fmt.Sprintf("Failure while contacting the jwk endpoint %v.", url),
			Err:        err,
			HTTPStatus: http.StatusUnauthorized,
		}
	}

	defer resp.Body.Close()

	if jwks, err = httpProv.decoder.decode(resp.Body); err != nil {
		return jwks, &ValidationError{
			Code:       ValidationErrorDecodeJwksFailure,
			Message:    fmt.Sprintf("Failure while decoding the jwk retrieved from the  endpoint %v.", url),
			Err:        err,
			HTTPStatus: http.StatusUnauthorized,
		}
	}

	return jwks, nil
}

type jsonJwksDecoder struct {
}

func (d *jsonJwksDecoder) decode(r io.Reader) (jose.JSONWebKeySet, error) {
	var jwks jose.JSONWebKeySet
	err := jsonDecodeResponse(r, &jwks)

	return jwks, err
}
