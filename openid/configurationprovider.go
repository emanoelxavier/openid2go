package openid

import (
	"fmt"
	"io"
	"net/http"
)

const wellKnownOpenIdConfiguration = "/.well-known/openid-configuration"

type httpGetFunc func(url string) (*http.Response, error)
type decodeResponseFunc func(io.Reader, interface{}) error

type configurationGetter interface { // Getter
	getConfiguration(string) (configuration, error)
}

type httpConfigurationProvider struct { //configurationProvider
	getConfig    httpGetFunc        //httpGetter
	decodeConfig decodeResponseFunc //responseDecoder
}

func (httpProv httpConfigurationProvider) getConfiguration(issuer string) (configuration, error) {
	configurationUri := issuer + wellKnownOpenIdConfiguration

	var config configuration
	resp, err := httpProv.getConfig(configurationUri) //http.Get(configurationUri)

	if err != nil {
		return config, &ValidationError{Code: ValidationErrorGetOpenIdConfigurationFailure, Message: fmt.Sprintf("Failure while contacting the configuration endpoint %v.", configurationUri), Err: err, HTTPStatus: http.StatusUnauthorized}
	}

	defer resp.Body.Close()

	if err := httpProv.decodeConfig(resp.Body, &config); /*json.NewDecoder(resp.Body).Decode(&configuration)*/ err != nil {
		return config, &ValidationError{Code: ValidationErrorDecodeOpenIdConfigurationFailure, Message: fmt.Sprintf("Failure while decoding the configuration retrived from endpoint %v.", configurationUri), Err: err, HTTPStatus: http.StatusUnauthorized}
	}

	return config, nil

}
