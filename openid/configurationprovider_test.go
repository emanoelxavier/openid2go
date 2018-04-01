package openid

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/mock"
)

type testBody struct {
	io.Reader
}

func (testBody) Close() error { return nil }

func TestConfigurationProvider_Get_UsesCorrectUrlAndRequest(t *testing.T) {
	httpGetter := &mockHttpGetter{}
	configurationProvider := httpConfigurationProvider{getter: httpGetter}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	issuer := "https://test"
	configSuffix := "/.well-known/openid-configuration"
	httpGetter.On("get", req, issuer+configSuffix).Return(nil, errors.New("Read configuration error"))

	_, e := configurationProvider.get(req, issuer)

	if e == nil {
		t.Error("An error was expected but not returned")
	}

	httpGetter.AssertExpectations(t)
}

func TestConfigurationProvider_Get_WhenGetReturnsError(t *testing.T) {
	httpGetter := &mockHttpGetter{}
	configurationProvider := httpConfigurationProvider{getter: httpGetter}

	readError := errors.New("Read configuration error")
	httpGetter.On("get", (*http.Request)(nil), mock.Anything).Return(nil, readError)

	_, e := configurationProvider.get(nil, "issuer")

	expectValidationError(t, e, ValidationErrorGetOpenIdConfigurationFailure, http.StatusUnauthorized, readError)

	httpGetter.AssertExpectations(t)
}

func TestConfigurationProvider_Get_WhenGetSucceeds(t *testing.T) {
	httpGetter := &mockHttpGetter{}
	configDecoder := &mockConfigurationDecoder{}
	configurationProvider := httpConfigurationProvider{httpGetter, configDecoder}

	respBody := "openid configuration"
	resp := &http.Response{Body: testBody{bytes.NewBufferString(respBody)}}

	httpGetter.On("get", (*http.Request)(nil), mock.Anything).Return(resp, nil)
	configDecoder.On("decode", mock.MatchedBy(ioReaderMatcher(t, respBody))).Return(configuration{}, nil)

	_, e := configurationProvider.get(nil, mock.Anything)

	if e != nil {
		t.Error("An error was returned but not expected", e)
	}

	httpGetter.AssertExpectations(t)
	configDecoder.AssertExpectations(t)
}

func TestConfigurationProvider_Get_WhenDecodeResponseReturnsError(t *testing.T) {
	httpGetter := &mockHttpGetter{}
	configDecoder := &mockConfigurationDecoder{}

	configurationProvider := httpConfigurationProvider{httpGetter, configDecoder}
	decodeError := errors.New("Decode configuration error")
	respBody := "openid configuration"
	resp := &http.Response{Body: testBody{bytes.NewBufferString(respBody)}}
	httpGetter.On("get", (*http.Request)(nil), mock.Anything).Return(resp, nil)

	configDecoder.On("decode", mock.MatchedBy(ioReaderMatcher(t, respBody))).Return(configuration{}, decodeError)
	_, e := configurationProvider.get(nil, mock.Anything)

	expectValidationError(t, e, ValidationErrorDecodeOpenIdConfigurationFailure, http.StatusUnauthorized, decodeError)

	httpGetter.AssertExpectations(t)
	configDecoder.AssertExpectations(t)
}

func TestConfigurationProvider_Get_WhenDecodeResponseSucceeds(t *testing.T) {
	httpGetter := &mockHttpGetter{}
	configDecoder := &mockConfigurationDecoder{}

	configurationProvider := httpConfigurationProvider{httpGetter, configDecoder}
	config := configuration{"testissuer", "https://testissuer/jwk"}
	respBody := "openid configuration"
	resp := &http.Response{Body: testBody{bytes.NewBufferString(respBody)}}
	httpGetter.On("get", (*http.Request)(nil), mock.Anything).Return(resp, nil)
	configDecoder.On("decode", mock.MatchedBy(ioReaderMatcher(t, respBody))).Return(config, nil)

	rc, e := configurationProvider.get(nil, mock.Anything)

	if e != nil {
		t.Error("An error was returned but not expected", e)
	}

	if rc.Issuer != config.Issuer {
		t.Error("Expected issuer", config.Issuer, "but was", rc.Issuer)
	}

	if rc.JwksURI != config.JwksURI {
		t.Error("Expected jwks uri", config.JwksURI, "but was", rc.JwksURI)
	}

	httpGetter.AssertExpectations(t)
}

func expectValidationError(t *testing.T, e error, vec ValidationErrorCode, status int, inner error) {
	if e == nil {
		t.Error("An error was expected but not returned")
	}

	if ve, ok := e.(*ValidationError); ok {
		if ve.Code != vec {
			t.Error("Expected error code", vec, "but was", ve.Code)
		}
		if ve.HTTPStatus != status {
			t.Error("Expected HTTP status", status, "but was", ve.HTTPStatus)
		}
		if inner != nil && ve.Err.Error() != inner.Error() {
			t.Error("Expected inner error", inner.Error(), ",but was", ve.Err.Error())
		}
	} else {
		t.Errorf("Expected error type '*ValidationError' but was %T", e)
	}
}

func ioReaderMatcher(t *testing.T, expectedContent string) func(r io.Reader) bool {
	return func(r io.Reader) bool {
		b, e := ioutil.ReadAll(r)

		assert.Nil(t, e, "error reading the content provided to decode")
		res := string(b) == expectedContent
		return res
	}
}
