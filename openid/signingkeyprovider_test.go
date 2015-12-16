package openid

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/square/go-jose"
)

func Test_getsigningKeys_WhenGetConfigurationReturnsError(t *testing.T) {
	configGetter, _, _, skProv := createSigningKeyProvider(t)

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
	configGetter, jwksGetter, _, skProv := createSigningKeyProvider(t)

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
	configGetter, jwksGetter, _, skProv := createSigningKeyProvider(t)

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
	configGetter, jwksGetter, pemEncoder, skProv := createSigningKeyProvider(t)

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

func Test_getsigningKeys_WhenKeyEncodingReturnsSuccess(t *testing.T) {
	configGetter, jwksGetter, pemEncoder, skProv := createSigningKeyProvider(t)

	keys := make([]jose.JsonWebKey, 2)
	encryptedKeys := make([]signingKey, 2)

	for i := 0; i < cap(keys); i = i + 1 {
		keys[i] = jose.JsonWebKey{KeyID: fmt.Sprintf("%v", i), Key: i}
		encryptedKeys[i] = signingKey{keyID: fmt.Sprintf("%v", i), key: []byte(fmt.Sprintf("%v", i))}
	}

	ejwks := jose.JsonWebKeySet{Keys: keys}
	go func() {
		configGetter.assertGetConfiguration(anything, configuration{}, nil)
		jwksGetter.assertGetJwks(anything, ejwks, nil)
		for i, encryptedKey := range encryptedKeys {
			pemEncoder.assertPEMEncodePublicKey(keys[i].Key, encryptedKey.key, nil)
		}
	}()

	sk, re := skProv.getSigningKeys(anything, anything)

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
}

func createSigningKeyProvider(t *testing.T) (*configurationGetterMock, *jwksGetterMock, *pemEncoderMock, signingKeyProvider) {
	configGetter := newConfigurationGetterMock(t)
	jwksGetter := newJwksGetterMock(t)
	pemEncoder := newPEMEncoderMock(t)

	skProv := signingKeyProvider{configGetter: configGetter, jwksGetter: jwksGetter, keyEncoder: pemEncoder.pemEncodePublicKey}
	return configGetter, jwksGetter, pemEncoder, skProv
}
