package openid

import (
	"net/http"
	"testing"

	"gopkg.in/square/go-jose.v2"
)

type jwksGetterMock struct {
	t     *testing.T
	Calls chan Call
}

func newJwksGetterMock(t *testing.T) *jwksGetterMock {
	return &jwksGetterMock{t, make(chan Call)}
}

type getJwksCall struct {
	req *http.Request
	url string
}

type getJwksResponse struct {
	jwks jose.JSONWebKeySet
	err  error
}

func (c *jwksGetterMock) getJwkSet(r *http.Request, url string) (jose.JSONWebKeySet, error) {
	c.Calls <- &getJwksCall{r, url}
	gr := (<-c.Calls).(*getJwksResponse)
	return gr.jwks, gr.err
}

func (c *jwksGetterMock) assertGetJwks(req *http.Request, url string, jwks jose.JSONWebKeySet, err error) {
	call := (<-c.Calls).(*getJwksCall)
	if call.req != req {
		c.t.Error("Expected getSigningKey with req", req, "but was", call.req)
	}
	if url != anything && call.url != url {
		c.t.Error("Expected getJwks with", url, "but was", call.url)
	}
	c.Calls <- &getJwksResponse{jwks, err}
}

func (c *jwksGetterMock) close() {
	close(c.Calls)
}

func (c *jwksGetterMock) assertDone() {
	if _, more := <-c.Calls; more {
		c.t.Fatal("Did not expect more calls.")
	}
}
