package openid

import "testing"

type signingKeyGetterMock struct {
	t     *testing.T
	Calls chan Call
}

func newSigningKeyGetterMock(t *testing.T) *signingKeyGetterMock {
	return &signingKeyGetterMock{t, make(chan Call)}
}

type getSigningKeysCall struct {
	iss string
}

type getSigningKeysResponse struct {
	keys []signingKey
	err  error
}

func (c *signingKeyGetterMock) getSigningKeys(iss string) ([]signingKey, error) {
	c.Calls <- &getSigningKeysCall{iss}
	sr := (<-c.Calls).(*getSigningKeysResponse)
	return sr.keys, sr.err
}

func (c *signingKeyGetterMock) assertGetSigningKeys(iss string, keys []signingKey, err error) {
	call := (<-c.Calls).(*getSigningKeysCall)
	if iss != anything && call.iss != iss {
		c.t.Error("Expected getSigningKeys with issuer", iss, "but was", call.iss)
	}
	c.Calls <- &getSigningKeysResponse{keys, err}
}

func (c *signingKeyGetterMock) close() {
	close(c.Calls)
}

func (c *signingKeyGetterMock) assertDone() {
	if _, more := <-c.Calls; more {
		c.t.Fatal("Did not expect more calls.")
	}
}
