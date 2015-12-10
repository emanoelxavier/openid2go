package openid

import (
	"io"
	"io/ioutil"
	"net/http"
	"testing"
)

type Call interface{}

const anything = "anything"

type ConfigurationClientMock struct {
	t     *testing.T
	Calls chan Call
}

func NewConfigurationClientMock(t *testing.T) *ConfigurationClientMock {
	return &ConfigurationClientMock{t, make(chan Call)}
}

type httpGetCall struct {
	url string
}

type httpGetResp struct {
	resp *http.Response
	err  error
}

type decodeResponseCall struct {
	reader io.Reader
}

type decodeResponseResp struct {
	value interface{}
	err   error
}

func (c *ConfigurationClientMock) httpGet(url string) (*http.Response, error) {
	c.Calls <- &httpGetCall{url}
	gr := (<-c.Calls).(*httpGetResp)
	return gr.resp, gr.err
}

func (c *ConfigurationClientMock) assertHttpGet(url string, resp *http.Response, err error) {
	call := (<-c.Calls).(*httpGetCall)
	if url != anything && call.url != url {
		c.t.Error("Expected httpGet with", url, "but was", call.url)
	}
	c.Calls <- &httpGetResp{resp, err}
}

func (c *ConfigurationClientMock) decodeResponse(reader io.Reader, value interface{}) error {
	c.Calls <- &decodeResponseCall{reader}
	dr := (<-c.Calls).(*decodeResponseResp)
	value = dr.value
	return dr.err
}

func (c *ConfigurationClientMock) assertDecodeResponse(response string, config *configuration, err error) {
	call := (<-c.Calls).(*decodeResponseCall)
	if response != anything {
		b, e := ioutil.ReadAll(call.reader)
		if e != nil {
			c.t.Error("Error while reading from the call reader", e)
		}
		s := string(b)

		if s != response {
			c.t.Error("Expected decodeResponse with", response, "but was", s)
		}
	}

	c.Calls <- &decodeResponseResp{config, err}
}

func (c *ConfigurationClientMock) close() {
	close(c.Calls)
}

func (c *ConfigurationClientMock) assertDone() {
	if _, more := <-c.Calls; more {
		c.t.Fatal("Did not expect more calls.")
	}
}
