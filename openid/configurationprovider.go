package openid

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const wellKnownOpenIDConfiguration = "/.well-known/openid-configuration"

type decodeResponseFunc func(io.Reader, interface{}) error

type configurationGetter interface { // Getter
	getConfiguration(r *http.Request, url string) (configuration, error)
}

type httpConfigurationProvider struct { //configurationProvider
	getConfig    HTTPGetFunc        //httpGetter
	decodeConfig decodeResponseFunc //responseDecoder
}

func newHTTPConfigurationProvider(gc HTTPGetFunc, dc decodeResponseFunc) *httpConfigurationProvider {
	return &httpConfigurationProvider{gc, dc}
}

func jsonDecodeResponse(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}

func (httpProv *httpConfigurationProvider) getConfiguration(r *http.Request, issuer string) (configuration, error) {
	// Workaround for tokens issued by google
	if issuer == "accounts.google.com" {
		issuer = "https://" + issuer
	}
	configurationURI := issuer + wellKnownOpenIDConfiguration
	var config configuration
	resp, err := httpProv.getConfig(r, configurationURI)
	if err != nil {
		return config, &ValidationError{
			Code:       ValidationErrorGetOpenIdConfigurationFailure,
			Message:    fmt.Sprintf("Failure while contacting the configuration endpoint %v.", configurationURI),
			Err:        err,
			HTTPStatus: http.StatusUnauthorized,
		}
	}

	defer resp.Body.Close()

	if err := httpProv.decodeConfig(resp.Body, &config); err != nil {
		return config, &ValidationError{
			Code:       ValidationErrorDecodeOpenIdConfigurationFailure,
			Message:    fmt.Sprintf("Failure while decoding the configuration retrived from endpoint %v.", configurationURI),
			Err:        err,
			HTTPStatus: http.StatusUnauthorized,
		}
	}

	return config, nil

}
