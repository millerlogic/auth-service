// Copyright (C) 2020 Christopher E. Miller
//
// This API definition is under the MIT license: https://mit-license.org/

// This is for types common to the API and the service implementation.
// Types only for the client API should not go here.

package auth

import (
	"strings"

	"github.com/dgrijalva/jwt-go"
)

type Token = jwt.Token

type TokenClaims = jwt.MapClaims

type TokenResult struct {
	Token    string `json:"token"`
	Name     string `json:"name"`
	Scopes   Scopes `json:"scopes"`
	Valid    bool   `json:"valid"`
	Exchange string `json:"exchange,omitempty"`
}

type Scopes []string

func (s *Scopes) UnmarshalText(text []byte) error {
	*s = strings.Split(string(text), " ")
	return nil
}

func (s Scopes) MarshalText() ([]byte, error) {
	return []byte(strings.Join(s, " ")), nil
}

func (s Scopes) Valid() bool {
	return s != nil
}

func (s Scopes) Has(scope string) bool {
	return strInStrs(scope, s) != -1
}

func (s Scopes) IsUser() bool {
	return s.Has("user")
}

func (s Scopes) IsService() bool {
	return s.Has("service")
}

func (s Scopes) IsMaster() bool {
	return s.Has("master")
}

// Returns index, or -1
func strInStrs(str string, strs []string) int {
	for i, x := range strs {
		if x == str {
			return i
		}
	}
	return -1
}

type GetUserResult struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Scopes Scopes `json:"scopes"`
}

type GetUserScopesResult struct {
	Name   string `json:"name"`
	Scopes Scopes `json:"scopes"`
}
