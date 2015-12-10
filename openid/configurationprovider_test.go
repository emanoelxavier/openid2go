package openid

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"
)

type testBody struct {
	io.Reader
}

func (testBody) Close() error { return nil }

func Test_getConfiguration_UsesCorrectUrl(t *testing.T) {
	c := NewConfigurationClientMock(t)
	configurationProvider := httpConfigurationProvider{configurationGetter: c.httpGet}

	issuer := "https://test"
	configSuffix := "/.well-known/openid-configuration"
	go func() {
		c.assertHttpGet(issuer+configSuffix, nil, errors.New("Read configuration error"))
		c.close()
	}()

	_, e := configurationProvider.getConfiguration(issuer)

	if e == nil {
		t.Error("An error was expected but not returned")
	}

	c.assertDone()
}

func Test_getConfiguration_WhenGetReturnsError(t *testing.T) {
	c := NewConfigurationClientMock(t)
	configurationProvider := httpConfigurationProvider{configurationGetter: c.httpGet}

	readError := errors.New("Read configuration error")
	go func() {
		c.assertHttpGet(anything, nil, readError)
		c.close()
	}()

	_, e := configurationProvider.getConfiguration("issuer")

	if e == nil {
		t.Error("An error was expected but not returned")
	}

	if ve, ok := e.(*ValidationError); ok {
		ee := ValidationErrorGetOpenIdConfigurationFailure
		es := http.StatusUnauthorized
		if ve.Code != ee {
			t.Error("Expected error code", ee, "but was", ve.Code)
		}
		if ve.HTTPStatus != es {
			t.Error("Expected HTTP status", es, "but was", ve.HTTPStatus)
		}
		if ve.Err.Error() != readError.Error() {
			t.Error("Expected inner error", readError.Error(), ",but was", ve.Err.Error())
		}
	} else {
		t.Errorf("Expected error type '*ValidationError' but was %T", e)
	}

	c.assertDone()
}

func Test_getConfiguration_WhenGetSucceeds(t *testing.T) {
	c := NewConfigurationClientMock(t)
	configurationProvider := httpConfigurationProvider{c.httpGet, c.decodeResponse}

	respBody := "openid configuration"
	resp := &http.Response{Body: testBody{bytes.NewBufferString(respBody)}}

	go func() {
		c.assertHttpGet(anything, resp, nil)
		c.assertDecodeResponse(respBody, nil, nil)
		c.close()
	}()

	config, e := configurationProvider.getConfiguration(anything)

	if e != nil {
		t.Error("An error was returned but not expected", e)
	}

	if config != nil {
		t.Error("The returned configuration should have been null, but was:", c)
	}

	c.assertDone()
}
