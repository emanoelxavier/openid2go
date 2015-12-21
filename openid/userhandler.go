package openid

import "net/http"

type UserHandler interface {
	ServeHTTPWithUser(*User, http.ResponseWriter, *http.Request)
}

type ServeHTTPWithUserFunc func(*User, http.ResponseWriter, *http.Request)

func (h ServeHTTPWithUserFunc) ServeHTTPWithUser(u *User, rw http.ResponseWriter, req *http.Request) {
	h(u, rw, req)
}
