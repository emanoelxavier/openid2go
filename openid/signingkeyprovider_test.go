package openid

import (
	"net/http"
	"testing"
)

func Test_getsigningKeys_WhenGetConfigurationReturnsError(t *testing.T) {
	configGetter := newConfigurationGetterMock(t)
	skProv := signingKeyProvider{configGetter: configGetter, jwksGetter: nil, keyEncoder: nil}
	ee := &ValidationError{Code: ValidationErrorGetOpenIdConfigurationFailure, HTTPStatus: http.StatusUnauthorized}

	go func() {
		configGetter.assertGetConfiguration(anything, configuration{}, ee)
	}()

	_, re := skProv.getSigningKeys(anything, anything)

	expectValidationError(t, re, ee.Code, ee.HTTPStatus, nil)
}
