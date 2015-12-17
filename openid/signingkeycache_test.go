package openid

import (
	"net/http"
	"testing"
)

func Test_getsigningKey_WhenKeyIsCached(t *testing.T) {
	_, keyCache := createSigningKeyMapCache(t)

	iss := "issuer"
	kid := "kid1"
	key := "signingKey"
	keyCache.jwksMap[iss] = []signingKey{{keyID: kid, key: []byte(key)}}

	expectKey(t, keyCache, iss, kid, key)
}

func Test_getsigningKey_WhenKeyIsNotCached_WhenProviderReturnsKey(t *testing.T) {
	keyGetter, keyCache := createSigningKeyMapCache(t)

	iss := "issuer"
	kid := "kid1"
	key := "signingKey"

	go func() {
		keyGetter.assertGetSigningKeys(iss, []signingKey{{keyID: kid, key: []byte(key)}}, nil)
		keyGetter.close()
	}()

	expectKey(t, keyCache, iss, kid, key)

	// Validate that the key is cached
	expectCachedKid(t, keyCache, iss, kid, key)

	keyGetter.assertDone()
}

func Test_getsigningKey_WhenProviderReturnsError(t *testing.T) {
	keyGetter, keyCache := createSigningKeyMapCache(t)

	iss := "issuer"
	kid := "kid1"
	ee := &ValidationError{Code: ValidationErrorGetJwksFailure, HTTPStatus: http.StatusUnauthorized}

	go func() {
		keyGetter.assertGetSigningKeys(iss, nil, ee)
		keyGetter.close()
	}()

	rk, re := keyCache.getSigningKey(iss, kid)

	expectValidationError(t, re, ee.Code, ee.HTTPStatus, nil)

	if rk != nil {
		t.Error("A key was returned but not expected")
	}

	cachedKeys := keyCache.jwksMap[iss]
	if len(cachedKeys) != 0 {
		t.Fatal("There shouldnt be cached keys for the targeted issuer.")
	}

	keyGetter.assertDone()
}

func Test_getsigningKey_WhenKeyIsNotFound(t *testing.T) {
	keyGetter, keyCache := createSigningKeyMapCache(t)

	iss := "issuer"
	kid := "kid1"
	tkid := "kid2"
	key := "signingKey"

	go func() {
		keyGetter.assertGetSigningKeys(iss, []signingKey{{keyID: kid, key: []byte(key)}}, nil)
		keyGetter.close()
	}()

	rk, re := keyCache.getSigningKey(iss, tkid)

	expectValidationError(t, re, ValidationErrorKidNotFound, http.StatusUnauthorized, nil)

	if rk != nil {
		t.Error("A key was returned but not expected")
	}

	expectCachedKid(t, keyCache, iss, kid, key)

	keyGetter.assertDone()
}

func Test_flushSigningKeys_FlushedKeysAreDeleted(t *testing.T) {
	_, keyCache := createSigningKeyMapCache(t)

	iss := "issuer"
	iss2 := "issuer2"
	kid := "kid1"
	key := "signingKey"
	keyCache.jwksMap[iss] = []signingKey{{keyID: kid, key: []byte(key)}}
	keyCache.jwksMap[iss2] = []signingKey{{keyID: kid, key: []byte(key)}}

	keyCache.flushSigningKeys(iss2)

	dk := keyCache.jwksMap[iss2]

	if dk != nil {
		t.Error("Flushed keys should not be in the cache.")
	}

	expectCachedKid(t, keyCache, iss, kid, key)
}

func Test_flushsigningKey_RetrieveFlushedKey(t *testing.T) {
	keyGetter, keyCache := createSigningKeyMapCache(t)

	iss := "issuer"
	kid := "kid1"
	key := "signingKey"

	go func() {
		keyGetter.assertGetSigningKeys(iss, []signingKey{{keyID: kid, key: []byte(key)}}, nil)
		keyGetter.assertGetSigningKeys(iss, []signingKey{{keyID: kid, key: []byte(key)}}, nil)

		keyGetter.close()
	}()

	// Get the signing key not yet cached will cache it.
	expectKey(t, keyCache, iss, kid, key)

	// Flush the signing keys for the given provider.
	keyCache.flushSigningKeys(iss)

	// Get the signing key will once again call the provider and cache the keys.

	expectKey(t, keyCache, iss, kid, key)

	// Validate that the key is cached
	expectCachedKid(t, keyCache, iss, kid, key)

	keyGetter.assertDone()
}

func expectCachedKid(t *testing.T, keyCache *signingKeyMapCache, iss string, kid string, key string) {

	cachedKeys := keyCache.jwksMap[iss]
	if len(cachedKeys) == 0 {
		t.Fatal("The keys were not cached as expected.")
	}

	foundKid := false
	for _, cachedKey := range cachedKeys {
		if cachedKey.keyID == kid {
			foundKid = true
			if keyStr := string(cachedKey.key); keyStr != key {
				t.Error("Expected key", key, "but got", keyStr)
			}

			continue
		}
	}

	if !foundKid {
		t.Error("A key with key id", kid, "was not found.")
	}
}

func expectKey(t *testing.T, c signingKeyCache, iss string, kid string, key string) {

	sk, re := c.getSigningKey(iss, kid)

	if re != nil {
		t.Error("An error was returned but not expected.")
	}

	if sk == nil {
		t.Fatal("The returned signing key should not be nil.")
	}

	keyStr := string(sk)

	if keyStr != key {
		t.Error("Expected key", key, "but got", keyStr)
	}
}

func createSigningKeyMapCache(t *testing.T) (*signingKeyGetterMock, *signingKeyMapCache) {
	mock := newSigningKeyGetterMock(t)
	return mock, newSigningKeyMapCache(mock)
}
