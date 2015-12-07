package openid

import (
	"fmt"
	"net/http"
	"testing"
)

var badHeaders = []struct {
	header     string
	errorCode  ValidationErrorCode
	httpStatus int
}{
	{"", ValidationErrorAuthorizationHeaderNotFound, http.StatusBadRequest},
	{"token", ValidationErrorAuthorizationHeaderWrongFormat, http.StatusBadRequest},
	{"token token token", ValidationErrorAuthorizationHeaderWrongFormat, http.StatusBadRequest},
	{"scheme token", ValidationErrorAuthorizationHeaderWrongSchemeName, http.StatusBadRequest},
	{"bearer token", ValidationErrorAuthorizationHeaderWrongSchemeName, http.StatusBadRequest},
	{"Bearer token token", ValidationErrorAuthorizationHeaderWrongFormat, http.StatusBadRequest},
}

func createRequest(ah string) http.Request {
	r := http.Request{}
	r.Header = http.Header(map[string][]string{})
	r.Header.Set("Authorization", ah)
	return r
}

func expectError(t *testing.T, e error, h string, c ValidationErrorCode, s int) {
	if ve, ok := e.(*ValidationError); ok {
		if ve.Code != c {
			t.Errorf("For header %v. Expected error code %v, got %v", h, c, ve.Code)
		}
		if ve.HTTPStatus != s {
			t.Errorf("For header %v. Expected http status %v, got %v", h, s, ve.HTTPStatus)
		}
	} else {
		t.Errorf("For header %v. Expected error type 'ValidationError', got %T", h, e)
	}
}

func Test_GetIdTokenAuthorizationHeader_WrongHeaderContent(t *testing.T) {
	for _, tt := range badHeaders {

		_, err := GetIdTokenAuthorizationHeader(createRequest(tt.header))
		expectError(t, err, tt.header, tt.errorCode, tt.httpStatus)
	}
}

func Test_GetIdTokenAuthorizationHeader_NoHeader(t *testing.T) {
	_, err := GetIdTokenAuthorizationHeader(http.Request{})

	expectError(t, err, "No Authorization Header", ValidationErrorAuthorizationHeaderNotFound, http.StatusBadRequest)
}

func Test_GetIdTokenAuthorizationHeader_CorrectHeaderContent(t *testing.T) {
	et := "token"
	hc := fmt.Sprintf("Bearer %v", et)
	rt, err := GetIdTokenAuthorizationHeader(createRequest(hc))

	if err != nil {
		t.Errorf("The header content %v is valid. Unexpected error", hc)
	}

	if rt != et {
		t.Errorf("Expected result %v, got %v", et, rt)
	}
}
