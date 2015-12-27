/*
Package openid implements web service middlewares for authenticating identities
represented by OpenID Connect (OIDC) ID Tokens.
For details on OpenID Connect see http://openid.net/specs/openid-connect-core-1_0.html

The middlewares will: extract the ID token from the request; retrieve the OIDC provider(OP)
configuration and signing keys; validate the token and provide the user identity and claims
to the underlying web service.

How to use

The main exported elements of this package are the Authenticate and AuthenticateUser middlewares.
In order to register either one of these middlewares to your service application pipeline you will need
an instance of the Configuration type that can be created using NewConfiguration.

       func Authenticate(conf *Configuration, h http.Handler) http.Handler
       func AuthenticateUser(conf *Configuration, h UserHandler) http.Handler
       NewConfiguration(options ...option) (*Configuration, error)

      Options:

       func ErrorHandler(eh ErrorHandlerFunc) func(*Configuration) error
       func ProvidersGetter(pg GetProvidersFunc) func(*Configuration) error

      Extension points:

       type ErrorHandlerFunc func(error, http.ResponseWriter, *http.Request) bool
       type GetProvidersFunc func() ([]Provider, error)

The example https://godoc.org/github.com/emanoelxavier/openid2go/openid#ex-package shows
how these elements work together.

Token parsing

Both Authenticate and AuthenticateUser middlewares will intercept incoming requests
and expect that they will contain an HTTP Authorization header with the content
'Bearer [idToken]' where [idToken] is a valid ID Token issued by an OP. For instance
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6...
Requests that do not contain a token with this format in the Authorization header will
not be forwarded to the next HTTP handler in the pipeline, instead they will fail back
to the client with HTTP status 400/Bad Request.
*/
package openid
