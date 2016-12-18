package openid

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/square/go-jose"
)

func Test_getJwkSet_UsesCorrectUrl(t *testing.T) {
	c := NewHTTPClientMock(t)
	jwksProvider := httpJwksProvider{getJwks: c.httpGet}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	url := "https://jwks"

	go func() {
		c.assertHTTPGet(req, url, nil, errors.New("Read configuration error"))
		c.close()
	}()

	_, e := jwksProvider.getJwkSet(req, url)

	if e == nil {
		t.Error("An error was expected but not returned")
	}

	c.assertDone()
}

func Test_getJwkSet_WhenGetReturnsError(t *testing.T) {
	c := NewHTTPClientMock(t)
	jwksProvider := httpJwksProvider{getJwks: c.httpGet}

	readError := errors.New("Read jwks error")
	go func() {
		c.assertHTTPGet(nil, anything, nil, readError)
		c.close()
	}()

	_, e := jwksProvider.getJwkSet(nil, anything)

	expectValidationError(t, e, ValidationErrorGetJwksFailure, http.StatusUnauthorized, readError)

	c.assertDone()
}

func Test_getJwkSet_WhenGetSucceeds(t *testing.T) {
	c := NewHTTPClientMock(t)
	jwksProvider := httpJwksProvider{c.httpGet, c.decodeResponse}

	respBody := "jwk set"
	resp := &http.Response{Body: testBody{bytes.NewBufferString(respBody)}}

	go func() {
		c.assertHTTPGet(nil, anything, resp, nil)
		c.assertDecodeResponse(respBody, nil, nil)
		c.close()
	}()

	_, e := jwksProvider.getJwkSet(nil, anything)

	if e != nil {
		t.Error("An error was returned but not expected", e)
	}

	c.assertDone()
}

func Test_getJwkSet_WhenDecodeResponseReturnsError(t *testing.T) {
	c := NewHTTPClientMock(t)
	jwksProvider := httpJwksProvider{c.httpGet, c.decodeResponse}
	decodeError := errors.New("Decode jwks error")
	respBody := "jwk set."
	resp := &http.Response{Body: testBody{bytes.NewBufferString(respBody)}}

	go func() {
		c.assertHTTPGet(nil, anything, resp, nil)
		c.assertDecodeResponse(anything, nil, decodeError)
		c.close()
	}()

	_, e := jwksProvider.getJwkSet(nil, anything)

	expectValidationError(t, e, ValidationErrorDecodeJwksFailure, http.StatusUnauthorized, decodeError)

	c.assertDone()
}

func Test_getJwkSet_WhenDecodeResponseSucceeds(t *testing.T) {
	c := NewHTTPClientMock(t)
	jwksProvider := httpJwksProvider{c.httpGet, c.decodeResponse}
	keys := []jose.JsonWebKey{
		{Key: "key1", Certificates: nil, KeyID: "keyid1", Algorithm: "algo1", Use: "use1"},
		{Key: "key2", Certificates: nil, KeyID: "keyid2", Algorithm: "algo2", Use: "use2"},
	}
	jwks := &jose.JsonWebKeySet{Keys: keys}
	respBody := "jwk set"
	resp := &http.Response{Body: testBody{bytes.NewBufferString(respBody)}}

	go func() {
		c.assertHTTPGet(nil, anything, resp, nil)
		c.assertDecodeResponse(anything, jwks, nil)
		c.close()
	}()

	rj, e := jwksProvider.getJwkSet(nil, anything)

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

	c.assertDone()
}
