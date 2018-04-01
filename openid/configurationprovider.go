package openid

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const wellKnownOpenIDConfiguration = "/.well-known/openid-configuration"

type configurationGetter interface {
	get(r *http.Request, url string) (configuration, error)
}

type configurationDecoder interface {
	decode(io.Reader) (configuration, error)
}

type httpGetter interface {
	get(r *http.Request, url string) (*http.Response, error)
}

func (f HTTPGetFunc) get(r *http.Request, url string) (*http.Response, error) {
	return f(r, url)
}

type httpConfigurationProvider struct {
	getter  httpGetter
	decoder configurationDecoder
}

func newHTTPConfigurationProvider(gc HTTPGetFunc, dc configurationDecoder) *httpConfigurationProvider {
	return &httpConfigurationProvider{gc, dc}
}

func (httpProv *httpConfigurationProvider) get(r *http.Request, issuer string) (configuration, error) {
	// Workaround for tokens issued by google
	if issuer == "accounts.google.com" {
		issuer = "https://" + issuer
	}
	configurationURI := issuer + wellKnownOpenIDConfiguration
	var config configuration
	resp, err := httpProv.getter.get(r, configurationURI)
	if err != nil {
		return config, &ValidationError{
			Code:       ValidationErrorGetOpenIdConfigurationFailure,
			Message:    fmt.Sprintf("Failure while contacting the configuration endpoint %v.", configurationURI),
			Err:        err,
			HTTPStatus: http.StatusUnauthorized,
		}
	}

	defer resp.Body.Close()

	if config, err = httpProv.decoder.decode(resp.Body); err != nil {
		return config, &ValidationError{
			Code:       ValidationErrorDecodeOpenIdConfigurationFailure,
			Message:    fmt.Sprintf("Failure while decoding the configuration retrived from endpoint %v.", configurationURI),
			Err:        err,
			HTTPStatus: http.StatusUnauthorized,
		}
	}

	return config, nil
}

func jsonDecodeResponse(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}

type jsonConfigurationDecoder struct {
}

func (d *jsonConfigurationDecoder) decode(r io.Reader) (configuration, error) {
	var config configuration
	err := jsonDecodeResponse(r, &config)

	return config, err
}
