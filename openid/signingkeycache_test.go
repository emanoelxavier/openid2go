package openid

import "testing"

func Test_getsigningKey_WhenKeyIsCached(t *testing.T) {
	_, keyCache := createSigningKeyMapCache(t)

	iss := "issuer"
	kid := "kid1"
	key := "signingKey"
	keyCache.jwksMap[iss] = []signingKey{{keyID: kid, key: []byte(key)}}

	sk, re := keyCache.getSigningKey(iss, kid)

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
