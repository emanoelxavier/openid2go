package openid

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
)

type pemEncoder interface {
	encode(key interface{}) ([]byte, error)
}

type pemPublicKeyEncoder struct {
}

func (e *pemPublicKeyEncoder) encode(key interface{}) ([]byte, error) {
	mk, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, &ValidationError{
			Code:       ValidationErrorMarshallingKey,
			Message:    fmt.Sprint("The jwk key could not be marshalled."),
			Err:        err,
			HTTPStatus: http.StatusInternalServerError,
		}
	}

	ed := pem.EncodeToMemory(&pem.Block{
		Bytes: mk,
	})

	return ed, nil
}
