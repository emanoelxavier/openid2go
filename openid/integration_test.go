// +build integration

package openid_test

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/emanoelxavier/openid2go/openid"
)

const authenticatedMessage string = "The user has been authenticated."

var idToken = flag.String("idToken", "", "a valid id token")
var issuer = flag.String("opIssuer", "", "the OP issuer")
var clientID = flag.String("clientID", "", "the client ID registered with the OP")

func authenticatedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, authenticatedMessage)
}

func Test_Authenticate_ValidIDToken(t *testing.T) {

	config, err := openid.NewConfiguration(openid.ProvidersGetter(getProviders))

	if err != nil {
		t.Fatal("Error whe creating the configuration for the openid middleware.")
	}

	ts := httptest.NewServer(openid.Authenticate(config, http.HandlerFunc(authenticatedHandler)))
	defer ts.Close()
	client := http.DefaultClient

	req, err := http.NewRequest("GET", ts.URL, nil)
	req.Header.Add("Authorization", "Bearer "+*idToken)
	resp, err := client.Do(req)

	if err != nil {
		t.Fatal(err)
	}

	msg, err := ioutil.ReadAll(resp.Body)

	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	if string(msg[:len(authenticatedMessage)]) != authenticatedMessage {
		t.Error("Expected response:", authenticatedMessage, "but got:", string(msg))
	}
}

func getProviders() ([]openid.Provider, error) {
	return []openid.Provider{{Issuer: *issuer, ClientIDs: []string{*clientID}}}, nil
}
