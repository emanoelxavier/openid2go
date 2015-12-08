package openid

import (
	"net/http"
	"testing"
)

type Call interface{}

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
	if call.url != url {
		c.t.Error("Expected httpGet with", url, "bu was", call.url)
	}
	c.Calls <- &httpGetResp{resp, err}
}

func (c *FakeConfigurationClient) close() {
	close(c.Calls)
}

func (c *FakeConfigurationClient) assertDone(t *testing.T) {
	if _, more := <-c.Calls; more {
		t.Fatal("Did not expect more calls.")
	}
}
