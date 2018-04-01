package openid

import (
	"fmt"
	"net/http"
)

type signingKeySetGetter interface {
	get(r *http.Request, issuer string) ([]signingKey, error)
}

type signingKeySetProvider struct {
	configGetter configurationGetter
	jwksGetter   jwksGetter
	keyEncoder   pemEncoder
}

type signingKey struct {
	keyID string
	key   []byte
}

func newSigningKeySetProvider(cg configurationGetter, jg jwksGetter, ke pemEncoder) *signingKeySetProvider {
	return &signingKeySetProvider{cg, jg, ke}
}

func (signProv *signingKeySetProvider) get(r *http.Request, iss string) ([]signingKey, error) {
	conf, err := signProv.configGetter.get(r, iss)

	if err != nil {
		return nil, err
	}

	jwks, err := signProv.jwksGetter.get(r, conf.JwksURI)

	if err != nil {
		return nil, err
	}

	if len(jwks.Keys) == 0 {
		return nil, &ValidationError{
			Code:       ValidationErrorEmptyJwk,
			Message:    fmt.Sprintf("The jwk set retrieved for the issuer %v does not contain any key.", iss),
			HTTPStatus: http.StatusUnauthorized,
		}
	}

	sk := make([]signingKey, len(jwks.Keys))

	for i, k := range jwks.Keys {
		ek, err := signProv.keyEncoder.encode(k.Key)
		if err != nil {
			return nil, err
		}

		sk[i] = signingKey{k.KeyID, ek}
	}

	return sk, nil
}
