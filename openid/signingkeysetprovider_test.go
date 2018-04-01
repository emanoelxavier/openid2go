package openid

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
	"gopkg.in/square/go-jose.v2"
)

func TestSigningKeySetProvider_Get_WhenGetConfigurationReturnsError(t *testing.T) {
	configGetter, _, _, skProv := createSigningKeySetProvider(t)

	ee := &ValidationError{Code: ValidationErrorGetOpenIdConfigurationFailure, HTTPStatus: http.StatusUnauthorized}
	configGetter.On("get", mock.Anything).Return(configuration{}, ee)

	sk, re := skProv.get(nil, mock.Anything)

	expectValidationError(t, re, ee.Code, ee.HTTPStatus, nil)

	if sk != nil {
		t.Error("The returned signing keys should be nil")
	}

	configGetter.AssertExpectations(t)
}

func TestSigningKeySetProvider_Get_WhenGetJwksReturnsError(t *testing.T) {
	configGetter, jwksGetter, _, skProv := createSigningKeySetProvider(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	ee := &ValidationError{Code: ValidationErrorGetJwksFailure, HTTPStatus: http.StatusUnauthorized}

	jwksGetter.On("get", req, mock.Anything).Return(jose.JSONWebKeySet{}, ee)

	configGetter.On("get", mock.Anything).Return(configuration{}, nil)

	sk, re := skProv.get(req, mock.Anything)

	expectValidationError(t, re, ee.Code, ee.HTTPStatus, nil)

	if sk != nil {
		t.Error("The returned signing keys should be nil")
	}

	configGetter.AssertExpectations(t)
	jwksGetter.AssertExpectations(t)
}

func TestSigningKeySetProvider_Get_WhenJwkSetIsEmpty(t *testing.T) {
	configGetter, jwksGetter, _, skProv := createSigningKeySetProvider(t)

	ee := &ValidationError{Code: ValidationErrorEmptyJwk, HTTPStatus: http.StatusUnauthorized}

	jwksGetter.On("get", (*http.Request)(nil), mock.Anything).Return(jose.JSONWebKeySet{}, nil)
	configGetter.On("get", mock.Anything).Return(configuration{}, nil)

	sk, re := skProv.get(nil, mock.Anything)

	expectValidationError(t, re, ee.Code, ee.HTTPStatus, nil)

	if sk != nil {
		t.Error("The returned signing keys should be nil")
	}

	configGetter.AssertExpectations(t)
	jwksGetter.AssertExpectations(t)
}

func TestSigningKeySetProvider_Get_WhenKeyEncodingReturnsError(t *testing.T) {
	configGetter, jwksGetter, pemEncoder, skProv := createSigningKeySetProvider(t)

	ee := &ValidationError{Code: ValidationErrorMarshallingKey, HTTPStatus: http.StatusInternalServerError}
	ejwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: nil}}}

	jwksGetter.On("get", (*http.Request)(nil), mock.Anything).Return(ejwks, nil)
	configGetter.On("get", mock.Anything).Return(configuration{}, nil)
	pemEncoder.On("encode", nil).Return(nil, ee)

	sk, re := skProv.get(nil, mock.Anything)

	expectValidationError(t, re, ee.Code, ee.HTTPStatus, nil)

	if sk != nil {
		t.Error("The returned signing keys should be nil")
	}

	configGetter.AssertExpectations(t)
	jwksGetter.AssertExpectations(t)
	pemEncoder.AssertExpectations(t)
}

func TestSigningKeySetProvider_Get_WhenKeyEncodingReturnsSuccess(t *testing.T) {
	configGetter, jwksGetter, pemEncoder, skProv := createSigningKeySetProvider(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	keys := make([]jose.JSONWebKey, 2)
	encryptedKeys := make([]signingKey, 2)

	for i := 0; i < cap(keys); i = i + 1 {
		keys[i] = jose.JSONWebKey{KeyID: fmt.Sprintf("%v", i), Key: i}
		encryptedKeys[i] = signingKey{keyID: fmt.Sprintf("%v", i), key: []byte(fmt.Sprintf("%v", i))}
	}

	ejwks := jose.JSONWebKeySet{Keys: keys}

	jwksGetter.On("get", req, mock.Anything).Return(ejwks, nil)
	configGetter.On("get", mock.Anything).Return(configuration{}, nil)

	for i, encryptedKey := range encryptedKeys {
		pemEncoder.On("encode", keys[i].Key).Return(encryptedKey.key, nil)
	}

	sk, re := skProv.get(req, mock.Anything)

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

	configGetter.AssertExpectations(t)
	jwksGetter.AssertExpectations(t)
	pemEncoder.AssertExpectations(t)
}

func createSigningKeySetProvider(t *testing.T) (*mockConfigurationGetter, *mockJwksGetter, *mockPemEncoder, signingKeySetProvider) {
	configGetter := &mockConfigurationGetter{}
	jwksGetter := &mockJwksGetter{}
	pemEncoder := &mockPemEncoder{}

	skProv := signingKeySetProvider{configGetter: configGetter, jwksGetter: jwksGetter, keyEncoder: pemEncoder}
	return configGetter, jwksGetter, pemEncoder, skProv
}
