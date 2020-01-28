// Copyright (C) 2020 Christopher E. Miller
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/rsa"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/millerlogic/auth-service/store"
	"github.com/ulule/limiter/v3"
	limiter_memory "github.com/ulule/limiter/v3/drivers/store/memory"
)

// TODO: don't use in-memory limit store.
var signupRateStore = limiter_memory.NewStoreWithOptions(limiter.StoreOptions{
	Prefix:          "",
	CleanUpInterval: limiter.DefaultCleanUpInterval,
})

// This limit is very easy to hit, override to change.
var SignupRateLimit = limiter.Rate{
	Period: 1 * time.Hour,
	Limit:  3,
}

// This limit is very easy to hit, override to change.
var SignupIPRateLimit = limiter.Rate{
	Period: 24 * time.Hour,
	Limit:  1,
}

var AllowUserSignup = true

func signupPOST(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !httpGetJSON(w, r, &payload) {
		return
	}

	_, fromScopes := httpTokenInfo(r)
	fromService := fromScopes.IsService()
	q := r.URL.Query()

	if !AllowUserSignup && !fromScopes.IsService() {
		// Need to check !IsService because checking for user doesn't work here!
		httpError(w, &UserError{http.StatusServiceUnavailable,
			"Signup services currently closed, please try again later"})
		return
	}

	// Check password:
	password := payload.Password
	noPassword := fromService && q.Get("no-password") == "1"
	if !noPassword {
		err := validatePassword(password)
		if err != nil {
			httpError(w, &Error{http.StatusBadRequest, err.Error()})
			return
		}
	}

	// Check email:
	email := payload.Email
	anyEmail := fromService && q.Get("any-email") == "1"
	if !anyEmail {
		err := validateEmail(email)
		if err != nil {
			httpError(w, &Error{http.StatusBadRequest, err.Error()})
			return
		}
	}

	// Check username:
	username := payload.Username
	err := validateUsername(username)
	if err != nil {
		httpError(w, &Error{http.StatusBadRequest, err.Error()})
		return
	}

	tx := httpBeginDB(w, r)
	if tx == nil {
		return
	}
	defer tx.RollbackUnlessCommitted()

	user, err := tx.GetUserByName(r.Context(), username)
	if err != nil && err != store.ErrNotFound {
		// Is it a timeout??
		log.Printf("ERROR unable to query db: %v", err)
		httpError(w, &Error{http.StatusUnauthorized,
			http.StatusText(http.StatusUnauthorized)})
		return
	}

	if user != nil {
		httpError(w, &UserError{http.StatusUnauthorized,
			"Username already registered, please choose another"})
		return
	}

	pwauth := ""
	if !noPassword {
		pwauth, err = genPasswordAuth(password)
		if err != nil {
			return
		}
	}

	remoteIP := limiter.GetIP(r, limiter.Options{
		TrustForwardHeader: fromScopes.Has("signup_proxy"),
	})

	// Make sure not too many signups...
	// This is done here so that we don't trip the limits just for checking for username availability.
	limitCtx, err := signupRateStore.Get(r.Context(), "", SignupRateLimit)
	if err != nil {
		log.Printf("ERROR signup limiter error: %v", err)
		httpError(w, &Error{http.StatusUnauthorized,
			http.StatusText(http.StatusUnauthorized)})
		return
	}
	limitipkey := maskIP(remoteIP).String()
	limitIPCtx, err := signupRateStore.Get(r.Context(), limitipkey, SignupIPRateLimit)
	if err != nil {
		log.Printf("ERROR signup IP limiter error: %v", err)
		httpError(w, &Error{http.StatusUnauthorized,
			http.StatusText(http.StatusUnauthorized)})
		return
	}

	if limitCtx.Reached || limitIPCtx.Reached {
		httpError(w, &UserError{429,
			"We're sorry, signups are limited at this time, please try again later"})
		return
	}

	now := time.Now()

	user = &store.UserModel{
		Name:      username,
		Email:     email,
		Auth:      pwauth,
		LastIP:    remoteIP.String(),
		TokenCode: 1,
		LastLogin: now,
		Created:   now,
	}

	err = tx.InsertUser(r.Context(), user)
	if err != nil {
		httpError(w, err)
		return
	}

	expiresAt := now.Add(5 * time.Minute)

	// This token expires quickly and is limited in scope
	// because it doesn't have all the options as login.
	// You can easily get a better token using the LTT.
	var scopes Scopes = []string{"user", "user_new", "user_unconfirmed"}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"iat":    now.Unix(),       // when the token was issued/created (now)
		"exp":    expiresAt.Unix(), // time when the token will expire
		"sub":    username,         // the subject/principal is whom the token is about
		"scopes": scopes,
		//"jti":    uuid.Must(uuid.NewV4()).String(), // a unique identifier for the token
		"id":    user.ID,
		"tcode": user.TokenCode,
	})

	// Sign token by private key
	privateKey := r.Context().Value(privkeyCtxKey).(*rsa.PrivateKey)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		httpError(w, err)
		return
	}
	token.Raw = signedToken
	token.Valid = true

	// Create LTT
	lttExpiresAt := now.Add(24 * time.Hour)
	var lttScopes Scopes = []string{"user_exchange_token"}
	ltt := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"iat":    now.Unix(),          // when the token was issued/created (now)
		"exp":    lttExpiresAt.Unix(), // time when the token will expire
		"sub":    username,            // the subject/principal is whom the token is about
		"scopes": lttScopes,
		//"jti":    uuid.Must(uuid.NewV4()).String(), // a unique identifier for the token
		"id":    user.ID,
		"tcode": user.TokenCode,
	})
	lttSignedToken, err := ltt.SignedString(privateKey)
	if err != nil {
		httpError(w, err)
		return
	}
	ltt.Raw = lttSignedToken
	ltt.Valid = true

	err = tx.Commit()
	if err != nil {
		httpError(w, err)
		return
	}

	log.Printf("* Signup user %s from %s %#v", user.Name, remoteIP, user)

	httpWriteJSON(w, http.StatusOK, getTokenResult(token, lttSignedToken))
}
