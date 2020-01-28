// Copyright (C) 2020 Christopher E. Miller
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	auth "github.com/millerlogic/auth-service/api"
)

// "Canon scopes" allow the service to grant users and other services scopes.
// A service's regular scopes cannot be granted to users.

// A service's tcode is mainly meant for accountability, and future blacklisting.

func createKeyPOST(w http.ResponseWriter, r *http.Request) {
	fromToken, fromScopes := httpTokenInfo(r)
	if !fromScopes.IsService() {
		httpError(w, &ScopeRequiredError{"service"})
		return
	}
	if fromToken == nil {
		return // Shouldn't happen if we found the service scope.
	}
	fromMaster := fromScopes.IsMaster()

	q := r.URL.Query()

	now := time.Now()
	duration, err := time.ParseDuration(q.Get("duration"))
	if err != nil {
		duration = 24 * time.Hour
	}

	namePlain := q.Get("name")
	if namePlain == "" || namePlain[0] == '$' || namePlain == "master" {
		httpError(w, &UserError{http.StatusBadRequest,
			"Invalid service name"})
		return
	}
	serviceName := "$" + namePlain

	fromClaims := fromToken.Claims.(jwt.MapClaims)
	var fromCanonScopes CanonScopes
	fromCanonScopes, _ = loadCanonScopes(fromClaims["canonScopes"])
	fromTCode, _ := fromClaims["tcode"].(float64)
	fromExpireUnix := fromClaims["iat"].(float64)
	fromExpireAt := time.Unix(int64(fromExpireUnix), 0)

	tcode := fromTCode // service tcode inherited, unless..
	tcodeReqStr := q.Get("tcode")
	tcodeReq, _ := strconv.ParseInt(tcodeReqStr, 10, 64)
	if tcodeReqStr != "" && (tcodeReq <= 0 || tcodeReq > 1<<52) {
		httpError(w, &UserError{http.StatusBadRequest,
			"requested tcode out of range"}) // 52-bit non-negative integer
		return
	}
	if tcodeReq != 0 {
		if fromMaster || fromScopes.Has("service_set_tcode") {
			tcode = float64(tcodeReq)
		} else {
			httpError(w, &ScopeRequiredError{"service_set_tcode"})
			return
		}
	}
	if tcode == 0 || math.IsNaN(tcode) { // no service tcode after all that, make one.
		rn, err := rand.Int(rand.Reader, big.NewInt(1<<52))
		if err != nil {
			httpError(w, err)
			return
		}
		tcode = float64(rn.Int64())
	}

	var canonScopes CanonScopes = parseCommaList(q.Get("canon-scopes"))
	if !fromMaster { // Check if canon scopes allowed if not master token:
		for _, canonScope := range canonScopes {
			if !fromCanonScopes.Allowed(canonScope) {
				httpError(w, &Error{http.StatusForbidden,
					"canon scope denied"})
				return
			}
		}
	}

	scopes := Scopes{"service"}
	for _, scope := range parseCommaList(q.Get("scopes")) {
		if !fromMaster && !fromScopes.Has(scope) && !fromCanonScopes.Allowed(scope) {
			httpError(w, &ScopeRequiredError{scope})
			return
		}
		if scope == "master" {
			httpError(w, &Error{http.StatusForbidden,
				"cannot grant master scope"})
			return
		}
		if scope == "user" || scope == "user_edit" {
			httpError(w, &Error{http.StatusForbidden,
				"cannot grant user scope"})
			return
		}
		if !scopes.Has(scope) {
			scopes = append(scopes, scope)
		}
	}

	// Make the new service token.
	expiresAt := now.Add(duration)
	if !fromMaster && expiresAt.After(fromExpireAt) {
		// Bound the expiration to the input token's expiration.
		expiresAt = fromExpireAt
	}
	claims := jwt.MapClaims{
		"iat":    now.Unix(),       // when the token was issued/created (now)
		"exp":    expiresAt.Unix(), // time when the token will expire
		"sub":    serviceName,      // the subject/principal is whom the token is about
		"scopes": scopes,
		"tcode":  tcode,
	}
	if canonScopes != nil {
		claims["canonScopes"] = canonScopes
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	// Sign token by private key
	privateKey := r.Context().Value(privkeyCtxKey).(*rsa.PrivateKey)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		httpError(w, err)
		return
	}
	token.Raw = signedToken
	token.Valid = true

	log.Printf("* Service token created: "+
		"from=%v sub=%v tcode=%v dur=%v canonScopes=%v scopes=%v",
		r.RemoteAddr, serviceName, tcode, expiresAt.Sub(now), canonScopes, scopes)

	httpWriteJSON(w, http.StatusOK, getTokenResult(token, ""))
}

type Scopes = auth.Scopes

type CanonScopes []string

func (s *CanonScopes) UnmarshalText(text []byte) error {
	*s = strings.Split(string(text), " ")
	return nil
}

func (s CanonScopes) MarshalText() ([]byte, error) {
	return []byte(strings.Join(s, " ")), nil
}

func (s CanonScopes) Allowed(checkCanonScope string) bool {
	for _, x := range s {
		if CanonScopeAllowed(x, checkCanonScope) {
			return true
		}
	}
	return false
}

func CanonScopeAllowed(canonScope, checkCanonScope string) bool {
	x := canonScope
	chk := checkCanonScope
	if x == chk {
		return true
	}
	if len(chk) > len(x) && chk[len(x)] == '_' && chk[:len(x)] == x {
		return true
	}
	return false
}

// GlobalScopes are the scopes all services can see.
// Defined as CanonScopes so that it can check Allowed and allow showing all sub scopes.
var GlobalScopes CanonScopes = []string{"user", "service", "master"}

func newMasterToken(expiresIn time.Duration, privateKey *rsa.PrivateKey) (*jwt.Token, error) {
	now := time.Now()
	expiresAt := now.Add(expiresIn)
	var scopes Scopes = []string{"master", "service", "admin"}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"iat":    now.Unix(),       // when the token was issued/created (now)
		"exp":    expiresAt.Unix(), // time when the token will expire
		"sub":    "$master",        // the subject/principal is whom the token is about
		"scopes": scopes,
		//"jti":    uuid.Must(uuid.NewV4()).String(), // a unique identifier for the token
		"id": 0,
	})
	if privateKey != nil {
		signedToken, err := token.SignedString(privateKey)
		if err != nil {
			return nil, err
		}
		token.Raw = signedToken
	}
	return token, nil
}
