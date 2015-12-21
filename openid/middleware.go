package openid

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

type Configuration struct {
	//	provGetter provGetter
	tokenValidator jwtTokenValidator
	idTokenGetter  GetIDTokenFunc
	errorHandler   ErrorHandlerFunc
}

type option func(*Configuration) error

func NewConfiguration(options ...option) (*Configuration, error) {
	m := new(Configuration)
	cp := newHTTPConfigurationProvider(http.Get, jsonDecodeResponse)
	jp := newHTTPJwksProvider(http.Get, jsonDecodeResponse)
	ksp := newSigningKeySetProvider(cp, jp, pemEncodePublicKey)
	kp := newSigningKeyProvider(ksp)
	m.tokenValidator = newIDTokenValidator(nil, jwt.Parse, kp)

	for _, option := range options {
		err := option(m)

		if err != nil {
			return nil, err
		}
	}

	return m, nil
}

func ProvidersGetter(pg getProvidersFunc) func(*Configuration) error {
	return func(c *Configuration) error {
		c.tokenValidator.(*idTokenValidator).provGetter = pg
		return nil
	}
}

func ErrorHandler(eh ErrorHandlerFunc) func(*Configuration) error {
	return func(c *Configuration) error {
		c.errorHandler = eh
		return nil
	}
}

type ErrorHandlerFunc func(error, http.ResponseWriter, *http.Request) bool

func ValidationErrorToHTTPStatus(e error, rw http.ResponseWriter, req *http.Request) (halt bool) {
	if verr, ok := e.(*ValidationError); ok {
		http.Error(rw, verr.Message, verr.HTTPStatus)
	} else {
		rw.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(rw, e.Error())
	}

	return true
}

func Authenticate(conf *Configuration, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, halt := authenticate(conf, w, r); !halt {
			h.ServeHTTP(w, r)
		}
	})
}

func AuthenticateUser(conf *Configuration, h UserHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, halt := authenticateUser(conf, w, r); !halt {
			h.ServeHTTPWithUser(u, w, r)
		}
	})
}

func authenticate(c *Configuration, rw http.ResponseWriter, req *http.Request) (t *jwt.Token, halt bool) {
	var tg GetIDTokenFunc
	if c.idTokenGetter == nil {
		tg = getIDTokenAuthorizationHeader
	} else {
		tg = c.idTokenGetter
	}

	var eh ErrorHandlerFunc
	if c.errorHandler == nil {
		eh = ValidationErrorToHTTPStatus
	} else {
		eh = c.errorHandler
	}

	ts, err := tg(*req)

	if err != nil {
		return nil, eh(err, rw, req)
	}

	vt, err := c.tokenValidator.validate(ts)

	if err != nil {
		return nil, eh(err, rw, req)
	}

	return vt, false

}

func authenticateUser(c *Configuration, rw http.ResponseWriter, req *http.Request) (u *User, halt bool) {
	var vt *jwt.Token

	var eh ErrorHandlerFunc
	if c.errorHandler == nil {
		eh = ValidationErrorToHTTPStatus
	} else {
		eh = c.errorHandler
	}

	if t, h := authenticate(c, rw, req); h {
		return nil, h
	} else {
		vt = t
	}

	u, err := newUser(vt)

	if err != nil {
		return nil, eh(err, rw, req)
	}

	return u, false

}
