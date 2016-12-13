package openid

type configuration struct {
	Issuer  string `json:"issuer"`
	JwksURI string `json:"jwks_uri"`
}
