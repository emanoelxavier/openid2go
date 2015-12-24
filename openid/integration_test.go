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

const authenticatedMessage string = "Congrats, you are authenticated!"

var idToken = flag.String("idToken", "", "a valid id token")
var issuer = flag.String("opIssuer", "", "the OP issuer")
var clientID = flag.String("clientID", "", "the client ID registered with the OP")

var server *httptest.Server

// The authenticateHandler is registered behind the openid.Authenticate middleware
func authenticatedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, authenticatedMessage)
}

// Init initiliazes the http.server to be used by the integration tests.
func init() {
	mux := http.NewServeMux()
	config, err := openid.NewConfiguration(openid.ProvidersGetter(getProviders))

	if err != nil {
		fmt.Println("Error whe creating the configuration for the openid middleware.", err)
	}

	mux.Handle("/authn", openid.Authenticate(config, http.HandlerFunc(authenticatedHandler)))

	server = httptest.NewServer(mux)
}

func Test_Authenticate_ValidIDToken(t *testing.T) {
	defer server.Close()

	client := http.DefaultClient

	req, err := http.NewRequest("GET", server.URL+"/authn", nil)
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

	msgs := string(msg[:len(authenticatedMessage)])
	if msgs != authenticatedMessage {
		t.Error("Expected response:", authenticatedMessage, "but got:", msgs)
	} else {
		t.Log(msgs)
	}
}

func getProviders() ([]openid.Provider, error) {
	return []openid.Provider{{Issuer: *issuer, ClientIDs: []string{*clientID}}}, nil
}
