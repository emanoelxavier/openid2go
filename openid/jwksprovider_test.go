package openid

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
	"gopkg.in/square/go-jose.v2"
)

func TestJwksProvider_Get_UsesCorrectUrl(t *testing.T) {
	httpGetter := &mockHTTPGetter{}
	jwksProvider := httpJwksProvider{getter: httpGetter}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	url := "https://jwks"

	httpGetter.On("get", req, url).Return(nil, errors.New("Read configuration error"))

	_, e := jwksProvider.get(req, url)

	if e == nil {
		t.Error("An error was expected but not returned")
	}

	httpGetter.AssertExpectations(t)
}

func TestJwksProvider_Get_WhenGetReturnsError(t *testing.T) {
	httpGetter := &mockHTTPGetter{}
	jwksProvider := httpJwksProvider{getter: httpGetter}

	readError := errors.New("Read jwks error")
	httpGetter.On("get", (*http.Request)(nil), mock.Anything).Return(nil, readError)

	_, e := jwksProvider.get(nil, mock.Anything)

	expectValidationError(t, e, ValidationErrorGetJwksFailure, http.StatusUnauthorized, readError)

	httpGetter.AssertExpectations(t)
}

func TestJwksProvider_Get_WhenGetSucceeds(t *testing.T) {
	httpGetter := &mockHTTPGetter{}
	jwksDecoder := &mockJwksDecoder{}
	jwksProvider := httpJwksProvider{httpGetter, jwksDecoder}

	respBody := "jwk set"
	resp := &http.Response{Body: testBody{bytes.NewBufferString(respBody)}}
	httpGetter.On("get", (*http.Request)(nil), mock.Anything).Return(resp, nil)
	jwksDecoder.On("decode", mock.MatchedBy(ioReaderMatcher(t, respBody))).Return(jose.JSONWebKeySet{}, nil)

	_, e := jwksProvider.get(nil, mock.Anything)

	if e != nil {
		t.Error("An error was returned but not expected", e)
	}

	httpGetter.AssertExpectations(t)
	jwksDecoder.AssertExpectations(t)
}

func TestJwksProvider_Get_WhenDecodeResponseReturnsError(t *testing.T) {
	httpGetter := &mockHTTPGetter{}
	jwksDecoder := &mockJwksDecoder{}

	jwksProvider := httpJwksProvider{httpGetter, jwksDecoder}
	decodeError := errors.New("Decode jwks error")
	respBody := "jwk set."
	resp := &http.Response{Body: testBody{bytes.NewBufferString(respBody)}}
	httpGetter.On("get", (*http.Request)(nil), mock.Anything).Return(resp, nil)
	jwksDecoder.On("decode", mock.Anything).Return(jose.JSONWebKeySet{}, decodeError)

	_, e := jwksProvider.get(nil, mock.Anything)

	expectValidationError(t, e, ValidationErrorDecodeJwksFailure, http.StatusUnauthorized, decodeError)

	httpGetter.AssertExpectations(t)
	jwksDecoder.AssertExpectations(t)
}

func TestJwksProvider_Get_WhenDecodeResponseSucceeds(t *testing.T) {
	httpGetter := &mockHTTPGetter{}
	jwksDecoder := &mockJwksDecoder{}

	jwksProvider := httpJwksProvider{httpGetter, jwksDecoder}
	keys := []jose.JSONWebKey{
		{Key: "key1", Certificates: nil, KeyID: "keyid1", Algorithm: "algo1", Use: "use1"},
		{Key: "key2", Certificates: nil, KeyID: "keyid2", Algorithm: "algo2", Use: "use2"},
	}
	jwks := jose.JSONWebKeySet{Keys: keys}
	respBody := "jwk set"
	resp := &http.Response{Body: testBody{bytes.NewBufferString(respBody)}}
	httpGetter.On("get", (*http.Request)(nil), mock.Anything).Return(resp, nil)
	jwksDecoder.On("decode", mock.Anything).Return(jwks, nil)

	rj, e := jwksProvider.get(nil, mock.Anything)

	if e != nil {
		t.Error("An error was returned but not expected", e)
	}

	if len(rj.Keys) != len(jwks.Keys) {
		t.Fatal("Expected", len(jwks.Keys), "keys, but got", len(rj.Keys))
	}

	for i, key := range rj.Keys {
		ek := jwks.Keys[i]
		if key.Algorithm != ek.Algorithm {
			t.Errorf("Key algorithm at %v should be %v, but was %v", i, ek.Algorithm, key.Algorithm)
		}
		if key.KeyID != ek.KeyID {
			t.Errorf("Key ID at %v should be %v, but was %v", i, ek.KeyID, key.KeyID)
		}
		if key.Key != ek.Key {
			t.Errorf("Key at %v should be %v, but was %v", i, ek.Key, key.Key)
		}
		if key.Use != ek.Use {
			t.Errorf("Key Use at %v should be %v, but was %v", i, ek.Use, key.Use)
		}
	}

	httpGetter.AssertExpectations(t)
	jwksDecoder.AssertExpectations(t)
}
