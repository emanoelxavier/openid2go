package openid

import (
	"fmt"
	"io"
	"net/http"
)

const wellKnownOpenIdConfiguration = "/.well-known/openid-configuration"

type httpGetFunc func(url string) (*http.Response, error)
type decodeResponseFunc func(io.Reader, interface{}) error

type configurationProvider interface {
	getConfiguration(string) (*configuration, error)
}

type httpConfigurationProvider struct {
	configurationGetter  httpGetFunc
	configurationDecoder decodeResponseFunc
}

func (httpProv httpConfigurationProvider) getConfiguration(issuer string) (*configuration, error) {
	configurationUri := issuer + wellKnownOpenIdConfiguration

	var config *configuration
	resp, err := httpProv.configurationGetter(configurationUri) //http.Get(configurationUri)

	if err != nil {
		return nil, &ValidationError{Code: ValidationErrorGetOpenIdConfigurationFailure, Message: fmt.Sprintf("Failure while contacting the configuration endpoint %v.", configurationUri), Err: err, HTTPStatus: http.StatusUnauthorized}
	}

	defer resp.Body.Close()

	if err := httpProv.configurationDecoder(resp.Body, &config); /*json.NewDecoder(resp.Body).Decode(&configuration)*/ err != nil {
		return nil, &ValidationError{Code: ValidationErrorDecodeOpenIdConfigurationFailure, Message: fmt.Sprintf("Failure while decoding the configuration retrived from endpoint %v.", configurationUri), Err: err, HTTPStatus: http.StatusUnauthorized}
	}

	return config, nil

}
