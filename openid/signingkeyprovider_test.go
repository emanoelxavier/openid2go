package openid

import (
	"net/http"
	"testing"

	"github.com/square/go-jose"
)

func Test_getsigningKeys_WhenGetConfigurationReturnsError(t *testing.T) {
	configGetter := newConfigurationGetterMock(t)
	skProv := signingKeyProvider{configGetter: configGetter, jwksGetter: nil, keyEncoder: nil}
	ee := &ValidationError{Code: ValidationErrorGetOpenIdConfigurationFailure, HTTPStatus: http.StatusUnauthorized}

	go func() {
		configGetter.assertGetConfiguration(anything, configuration{}, ee)
	}()

	sk, re := skProv.getSigningKeys(anything, anything)

	expectValidationError(t, re, ee.Code, ee.HTTPStatus, nil)

	if sk != nil {
		t.Error("The returned signing keys should be nil")
	}
}

func Test_getsigningKeys_WhenGetJwksReturnsError(t *testing.T) {
	configGetter := newConfigurationGetterMock(t)
	jwksGetter := newJwksGetterMock(t)
	skProv := signingKeyProvider{configGetter: configGetter, jwksGetter: jwksGetter, keyEncoder: nil}
	ee := &ValidationError{Code: ValidationErrorGetJwksFailure, HTTPStatus: http.StatusUnauthorized}

	go func() {
		configGetter.assertGetConfiguration(anything, configuration{}, nil)
		jwksGetter.assertGetJwks(anything, jose.JsonWebKeySet{}, ee)

	}()

	sk, re := skProv.getSigningKeys(anything, anything)

	expectValidationError(t, re, ee.Code, ee.HTTPStatus, nil)

	if sk != nil {
		t.Error("The returned signing keys should be nil")
	}

}

func Test_getsigningKeys_WhenJwkSetIsEmpty(t *testing.T) {
	configGetter := newConfigurationGetterMock(t)
	jwksGetter := newJwksGetterMock(t)
	skProv := signingKeyProvider{configGetter: configGetter, jwksGetter: jwksGetter, keyEncoder: nil}
	ee := &ValidationError{Code: ValidationErrorEmptyJwk, HTTPStatus: http.StatusUnauthorized}

	go func() {
		configGetter.assertGetConfiguration(anything, configuration{}, nil)
		jwksGetter.assertGetJwks(anything, jose.JsonWebKeySet{}, nil)

	}()

	sk, re := skProv.getSigningKeys(anything, anything)

	expectValidationError(t, re, ee.Code, ee.HTTPStatus, nil)

	if sk != nil {
		t.Error("The returned signing keys should be nil")
	}
}

func Test_getsigningKeys_WhenKeyEncodingReturnsError(t *testing.T) {
	configGetter := newConfigurationGetterMock(t)
	jwksGetter := newJwksGetterMock(t)
	pemEncoder := newPEMEncoderMock(t)

	skProv := signingKeyProvider{configGetter: configGetter, jwksGetter: jwksGetter, keyEncoder: pemEncoder.pemEncodePublicKey}
	ee := &ValidationError{Code: ValidationErrorMarshallingKey, HTTPStatus: http.StatusInternalServerError}
	ejwks := jose.JsonWebKeySet{Keys: []jose.JsonWebKey{{Key: nil}}}

	go func() {
		configGetter.assertGetConfiguration(anything, configuration{}, nil)
		jwksGetter.assertGetJwks(anything, ejwks, nil)
		pemEncoder.assertPEMEncodePublicKey(nil, nil, ee)
	}()

	sk, re := skProv.getSigningKeys(anything, anything)

	expectValidationError(t, re, ee.Code, ee.HTTPStatus, nil)

	if sk != nil {
		t.Error("The returned signing keys should be nil")
	}
}
