package openid

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

type SetupErrorCode uint32
type ValidationErrorCode uint32

const (
	SetupErrorInvalidIssuer SetupErrorCode = iota
	SetupErrorInvalidClientIds
	SetupErrorEmptyProviderCollection
)

const (
	ValidationErrorAuthorizationHeaderNotFound ValidationErrorCode = iota
	ValidationErrorAuthorizationHeaderWrongFormat
	ValidationErrorAuthorizationHeaderWrongSchemeName
	ValidationErrorJwtValidationFailure
	ValidationErrorJwtValidationUnknownFailure
	ValidationErrorInvalidAudienceType
	ValidationErrorInvalidAudience
	ValidationErrorAudienceNotFound
	ValidationErrorInvalidIssuerType
	ValidationErrorInvalidIssuer
	ValidationErrorIssuerNotFound
	ValidationErrorGetOpenIdConfigurationFailure
	ValidationErrorDecodeOpenIdConfigurationFailure
	ValidationErrorGetJwkFailure
	ValidationErrorDecodeJwkFailure
	ValidationErrorEmptyJwk
	ValidationErrorEmptyJwkKey
	ValidationErrorMarshallingKey
	ValidationErrorKidNotFound
	ValidationErrorInvalidSubjectType
	ValidationErrorInvalidSubject
	ValidationErrorSubjectNotFound
	ValidationErrorIdTokenEmpty
)

type SetupError struct {
	Err     error
	Code    SetupErrorCode
	Message string
}

func (se SetupError) Error() string {
	return fmt.Sprintf("Error during middleware setup: %v", se.Message)
}

type ValidationError struct {
	Err        error
	Code       ValidationErrorCode
	Message    string
	HTTPStatus int
}

func (se ValidationError) Error() string {
	return fmt.Sprintf("Error token validation: %v", se.Message)
}

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
