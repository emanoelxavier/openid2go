// Package openid implements middlewares to perform validation of OIDC (OpenId Connect)
// id tokens and make available the identity of the authenticated user.
package openid

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

// SetupErrorCode is the type of error code that can
// be returned by the operations done during middleware setup.
type SetupErrorCode uint32

// Setup error constants.
const (
	SetupErrorInvalidIssuer           SetupErrorCode = iota // Invalid issuer provided during setup.
	SetupErrorInvalidClientIDs                              // Invalid client id collection provided during setup.
	SetupErrorEmptyProviderCollection                       // Empty collection of providers provided during setup.
)

// ValidationErrorCode is the type of error code that can
// be returned by the operations done during token validation.
type ValidationErrorCode uint32

// Validation error constants.
const (
	ValidationErrorAuthorizationHeaderNotFound        ValidationErrorCode = iota // Authorization header not found on request.
	ValidationErrorAuthorizationHeaderWrongFormat                                // Authorization header unexpected format.
	ValidationErrorAuthorizationHeaderWrongSchemeName                            // Authorization header unexpected scheme.
	ValidationErrorJwtValidationFailure                                          // Jwt token validation failed with a known error.
	ValidationErrorJwtValidationUnknownFailure                                   // Jwt token validation failed with an unknown error.
	ValidationErrorInvalidAudienceType                                           // Unexpected token audience type.
	ValidationErrorInvalidAudience                                               // Unexpected token audience content.
	ValidationErrorAudienceNotFound                                              // Unexpected token audience value. Audience not registered.
	ValidationErrorInvalidIssuerType                                             // Unexpected token issuer type.
	ValidationErrorInvalidIssuer                                                 // Unexpected token issuer content.
	ValidationErrorIssuerNotFound                                                // Unexpected token value. Issuer not registered.
	ValidationErrorGetOpenIdConfigurationFailure                                 // Failure while retrieving the OIDC configuration.
	ValidationErrorDecodeOpenIdConfigurationFailure                              // Failure while decoding the OIDC configuration.
	ValidationErrorGetJwksFailure                                                // Failure while retrieving jwk set.
	ValidationErrorDecodeJwksFailure                                             // Failure while decoding the jwk set.
	ValidationErrorEmptyJwk                                                      // Empty jwk returned.
	ValidationErrorEmptyJwkKey                                                   // Empty jwk key set returned.
	ValidationErrorMarshallingKey                                                // Error while marshalling the signing key.
	ValidationErrorKidNotFound                                                   // Key identifier not found.
	ValidationErrorInvalidSubjectType                                            // Unexpected token subject type.
	ValidationErrorInvalidSubject                                                // Unexpected token subject content.
	ValidationErrorSubjectNotFound                                               // Token missing the 'sub' claim.
	ValidationErrorIdTokenEmpty                                                  // Empty ID token.
	ValidationErrorEmptyProviders                                                // Empty collection of providers.
)

// SetupError represents the error returned by operations called during
// middleware setup.
type SetupError struct {
	Err     error
	Code    SetupErrorCode
	Message string
}

// Error returns a formatted string containing the error Message.
func (se SetupError) Error() string {
	return fmt.Sprintf("Error during middleware setup: %v", se.Message)
}

// ValidationError represents the error returned by operations called during
// token validation.
type ValidationError struct {
	Err        error
	Code       ValidationErrorCode
	Message    string
	HTTPStatus int
}

// Error returns a formatted string containing the error Message.
func (se ValidationError) Error() string {
	return fmt.Sprintf("Error token validation: %v", se.Message)
}

// jwtErrorToOpenIdError converts errors of the type *jwt.ValidationError returned during token validation into errors of type *ValidationError
func jwtErrorToOpenIdError(e error) *ValidationError {
	if jwtError, ok := e.(*jwt.ValidationError); ok {
		if (jwtError.Errors & (jwt.ValidationErrorNotValidYet | jwt.ValidationErrorExpired | jwt.ValidationErrorSignatureInvalid)) != 0 {
			return &ValidationError{Code: ValidationErrorJwtValidationFailure, Message: "Jwt token validation failed.", HTTPStatus: http.StatusUnauthorized}
		}

		if (jwtError.Errors & jwt.ValidationErrorMalformed) != 0 {
			return &ValidationError{Code: ValidationErrorJwtValidationFailure, Message: "Jwt token validation failed.", HTTPStatus: http.StatusBadRequest}
		}
	}

	return &ValidationError{Code: ValidationErrorJwtValidationUnknownFailure, Message: "Jwt token validation failed with unknown error.", HTTPStatus: http.StatusInternalServerError}
}
