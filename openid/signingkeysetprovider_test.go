package openid

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
	"gopkg.in/square/go-jose.v2"
)

func Test_getsigningKeySet_WhenGetConfigurationReturnsError(t *testing.T) {
	configGetter, _, _, skProv := createSigningKeySetProvider(t)

	ee := &ValidationError{Code: ValidationErrorGetOpenIdConfigurationFailure, HTTPStatus: http.StatusUnauthorized}

	go func() {
		configGetter.assertGetConfiguration(anything, configuration{}, ee)
		configGetter.close()
	}()

	sk, re := skProv.getSigningKeySet(nil, anything)

	expectValidationError(t, re, ee.Code, ee.HTTPStatus, nil)

	if sk != nil {
		t.Error("The returned signing keys should be nil")
	}

	configGetter.assertDone()
}

func Test_getsigningKeySet_WhenGetJwksReturnsError(t *testing.T) {
	configGetter, jwksGetter, _, skProv := createSigningKeySetProvider(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	ee := &ValidationError{Code: ValidationErrorGetJwksFailure, HTTPStatus: http.StatusUnauthorized}

	jwksGetter.On("getJwkSet", req, mock.Anything).Return(jose.JSONWebKeySet{}, ee)

	go func() {
		configGetter.assertGetConfiguration(anything, configuration{}, nil)
		configGetter.close()
	}()

	sk, re := skProv.getSigningKeySet(req, anything)

	expectValidationError(t, re, ee.Code, ee.HTTPStatus, nil)

	if sk != nil {
		t.Error("The returned signing keys should be nil")
	}

	configGetter.assertDone()
	jwksGetter.AssertExpectations(t)
}

func Test_getsigningKeySet_WhenJwkSetIsEmpty(t *testing.T) {
	configGetter, jwksGetter, _, skProv := createSigningKeySetProvider(t)

	ee := &ValidationError{Code: ValidationErrorEmptyJwk, HTTPStatus: http.StatusUnauthorized}

	jwksGetter.On("getJwkSet", (*http.Request)(nil), mock.Anything).Return(jose.JSONWebKeySet{}, nil)
	go func() {
		configGetter.assertGetConfiguration(anything, configuration{}, nil)
		configGetter.close()
	}()

	sk, re := skProv.getSigningKeySet(nil, anything)

	expectValidationError(t, re, ee.Code, ee.HTTPStatus, nil)

	if sk != nil {
		t.Error("The returned signing keys should be nil")
	}

	configGetter.assertDone()
	jwksGetter.AssertExpectations(t)
}

func Test_getsigningKeySet_WhenKeyEncodingReturnsError(t *testing.T) {
	configGetter, jwksGetter, pemEncoder, skProv := createSigningKeySetProvider(t)

	ee := &ValidationError{Code: ValidationErrorMarshallingKey, HTTPStatus: http.StatusInternalServerError}
	ejwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: nil}}}

	jwksGetter.On("getJwkSet", (*http.Request)(nil), mock.Anything).Return(ejwks, nil)

	go func() {
		configGetter.assertGetConfiguration(anything, configuration{}, nil)
		configGetter.close()
		pemEncoder.assertPEMEncodePublicKey(nil, nil, ee)
		pemEncoder.close()
	}()

	sk, re := skProv.getSigningKeySet(nil, anything)

	expectValidationError(t, re, ee.Code, ee.HTTPStatus, nil)

	if sk != nil {
		t.Error("The returned signing keys should be nil")
	}

	configGetter.assertDone()
	jwksGetter.AssertExpectations(t)
	pemEncoder.assertDone()
}

func Test_getsigningKeySet_WhenKeyEncodingReturnsSuccess(t *testing.T) {
	configGetter, jwksGetter, pemEncoder, skProv := createSigningKeySetProvider(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	keys := make([]jose.JSONWebKey, 2)
	encryptedKeys := make([]signingKey, 2)

	for i := 0; i < cap(keys); i = i + 1 {
		keys[i] = jose.JSONWebKey{KeyID: fmt.Sprintf("%v", i), Key: i}
		encryptedKeys[i] = signingKey{keyID: fmt.Sprintf("%v", i), key: []byte(fmt.Sprintf("%v", i))}
	}

	ejwks := jose.JSONWebKeySet{Keys: keys}

	jwksGetter.On("getJwkSet", req, mock.Anything).Return(ejwks, nil)

	go func() {
		configGetter.assertGetConfiguration(anything, configuration{}, nil)
		for i, encryptedKey := range encryptedKeys {
			pemEncoder.assertPEMEncodePublicKey(keys[i].Key, encryptedKey.key, nil)
		}
		configGetter.close()
		pemEncoder.close()
	}()

	sk, re := skProv.getSigningKeySet(req, anything)

	if re != nil {
		t.Error("An error was returned but not expected.")
	}

	if sk == nil {
		t.Fatal("The returned signing keys should be not nil")
	}

	if len(sk) != len(encryptedKeys) {
		t.Error("Returned", len(sk), "encrypted keys, but expected", len(encryptedKeys))
	}

	for i, encryptedKey := range encryptedKeys {
		if encryptedKey.keyID != sk[i].keyID {
			t.Error("Key at", i, "should have keyID", encryptedKey.keyID, "but was", sk[i].keyID)
		}
		if string(encryptedKey.key) != string(sk[i].key) {
			t.Error("Key at", i, "should be", encryptedKey.key, "but was", sk[i].key)
		}
	}

	configGetter.assertDone()
	jwksGetter.AssertExpectations(t)
	pemEncoder.assertDone()
}

func createSigningKeySetProvider(t *testing.T) (*configurationGetterMock, *mockJwksGetter, *pemEncoderMock, signingKeySetProvider) {
	configGetter := newConfigurationGetterMock(t)
	jwksGetter := &mockJwksGetter{}
	pemEncoder := newPEMEncoderMock(t)

	skProv := signingKeySetProvider{configGetter: configGetter, jwksGetter: jwksGetter, keyEncoder: pemEncoder.pemEncodePublicKey}
	return configGetter, jwksGetter, pemEncoder, skProv
}
