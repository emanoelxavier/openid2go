package openid

import (
	"errors"
	"net/http"
	"testing"
)

type Call interface{}

const anything = "anything"

type FakeConfigurationClient struct {
	t     *testing.T
	Calls chan Call
}

func NewFakeConfigurationClient(t *testing.T) *FakeConfigurationClient {
	return &FakeConfigurationClient{t, make(chan Call)}
}

type httpGetCall struct {
	url string
}

type httpGetResp struct {
	resp *http.Response
	err  error
}

func (c *FakeConfigurationClient) httpGet(url string) (*http.Response, error) {
	c.Calls <- &httpGetCall{url}
	gr := (<-c.Calls).(*httpGetResp)
	return gr.resp, gr.err
}

func (c *FakeConfigurationClient) assertHttpGet(url string, resp *http.Response, err error) {
	call := (<-c.Calls).(*httpGetCall)
	if url != anything && call.url != url {
		c.t.Error("Expected httpGet with", url, "but was", call.url)
	}
	c.Calls <- &httpGetResp{resp, err}
}

func (c *FakeConfigurationClient) close() {
	close(c.Calls)
}

func (c *FakeConfigurationClient) assertDone() {
	if _, more := <-c.Calls; more {
		c.t.Fatal("Did not expect more calls.")
	}
}

func Test_getConfiguration_UsesCorrectUrl(t *testing.T) {
	c := NewFakeConfigurationClient(t)
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
	c := NewFakeConfigurationClient(t)
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
	c := NewFakeConfigurationClient(t)
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
