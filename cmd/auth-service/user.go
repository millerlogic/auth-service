// Copyright (C) 2020 Christopher E. Miller
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dgrijalva/jwt-go"
	auth "github.com/millerlogic/auth-service/api"
	"github.com/millerlogic/auth-service/store"
	"gopkg.in/hlandau/passlib.v1/hash/bcryptsha256"
)

func updateUserPOST(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Updates map[string]interface{} `json:"updates"`
	}
	if !httpGetJSON(w, r, &payload) {
		return
	}
	if payload.Updates == nil || len(payload.Updates) == 0 {
		httpError(w, &Error{http.StatusBadRequest,
			"no updates specified"})
		return
	}

	tx := httpBeginDB(w, r)
	if tx == nil {
		return
	}
	defer tx.RollbackUnlessCommitted()

	user, _, scopes := httpUser(w, r, tx)
	if user == nil {
		return
	}

	if !scopes.Has("user_edit") {
		httpError(w, &ScopeRequiredError{"user_edit"})
		return
	}

	var fieldNames []string
	for name, value := range payload.Updates {
		switch name {
		case "email":
			email, ok := value.(string)
			if !ok {
				httpError(w, &Error{http.StatusBadRequest,
					"string required for: " + name})
				return
			}
			if err := validateEmail(email); err != nil {
				httpError(w, &Error{http.StatusBadRequest, err.Error()})
				return
			}
			user.Email = email
			fieldNames = append(fieldNames, "Email")
		case "password":
			password, ok := value.(string)
			if !ok {
				httpError(w, &Error{http.StatusBadRequest,
					"string required for: " + name})
				return
			}
			if err := validatePassword(password); err != nil {
				httpError(w, &Error{http.StatusBadRequest, err.Error()})
				return
			}
			pwauth, err := genPasswordAuth(password)
			if err != nil {
				return
			}
			user.Auth = pwauth
			fieldNames = append(fieldNames, "Auth")
		default:
			httpError(w, &Error{http.StatusBadRequest,
				"unsupported update: " + name})
			return
		}
	}

	if len(fieldNames) > 0 {
		err := tx.UpdateUser(r.Context(), user, fieldNames...)
		if err != nil {
			httpError(w, err)
			return
		}

		err = tx.Commit()
		if err != nil {
			httpError(w, err)
			return
		}
	}

	httpWriteOK(w)
}

func getUserGET(w http.ResponseWriter, r *http.Request) {
	tx := httpBeginDB(w, r)
	if tx == nil {
		return
	}
	defer tx.RollbackUnlessCommitted()

	user, _, scopes := httpUser(w, r, tx)
	if user == nil {
		return
	}

	if !scopes.IsUser() {
		httpError(w, &ScopeRequiredError{"user"})
		return
	}

	// allScopes will be a [distinct] union of:
	// current scopes, and all this user's scopes in the db.
	allScopes := append(Scopes(nil), scopes...)

	userScopes, err := tx.GetUserScopes(r.Context(), user.ID)
	if err != nil {
		httpError(w, err)
		return
	}

	for _, userScope := range userScopes {
		if !allScopes.Has(userScope.Name) {
			allScopes = append(allScopes, userScope.Name)
		}
	}

	httpWriteJSON(w, http.StatusOK, &auth.GetUserResult{
		ID:     user.ID,
		Name:   user.Name,
		Email:  user.Email,
		Scopes: allScopes,
	})
}

// Invalidates all exchange tokens for the user, needs user_edit scope.
// Note: some active access tokens might continue to work until expiration,
// if they don't directly access the user db record.
func invalidatePOST(w http.ResponseWriter, r *http.Request) {
	tx := httpBeginDB(w, r)
	if tx == nil {
		return
	}
	defer tx.RollbackUnlessCommitted()

	user, _, scopes := httpUser(w, r, tx)
	if user == nil {
		return
	}

	if !scopes.Has("user_edit") {
		httpError(w, &ScopeRequiredError{"user_edit"})
		return
	}

	user.TokenCode++
	err := tx.UpdateUser(r.Context(), user, "TokenCode")
	if err != nil {
		httpError(w, err)
		return
	}

	err = tx.Commit()
	if err != nil {
		httpError(w, err)
		return
	}

	httpWriteOK(w)
}

// Get scopes for a particular user (service call)
// Otherwise use /validate to get current user's scopes.
func getUserScopesGET(w http.ResponseWriter, r *http.Request) {
	fromToken, fromScopes := httpTokenInfo(r)
	if !fromScopes.IsService() {
		httpError(w, &ScopeRequiredError{"service"})
		return
	}
	if fromToken == nil {
		return // Shouldn't happen if we found the service scope.
	}
	fromMaster := fromScopes.IsMaster()

	fromClaims := fromToken.Claims.(jwt.MapClaims)
	var fromCanonScopes CanonScopes
	fromCanonScopes, _ = loadCanonScopes(fromClaims["canonScopes"])

	q := r.URL.Query()
	username := q.Get("user")
	if username == "" {
		httpError(w, &Error{http.StatusBadRequest, "missing parameter"})
		return
	}

	tx := httpBeginDB(w, r)
	if tx == nil {
		return
	}
	defer tx.RollbackUnlessCommitted()

	user, err := tx.GetUserByName(r.Context(), username)
	if err != nil {
		httpError(w, &UserError{http.StatusBadRequest,
			"Invalid username"})
		return
	}

	scopes, err := tx.GetUserScopes(r.Context(), user.ID)
	if err != nil {
		httpError(w, err)
		return
	}

	var returnScopes Scopes = []string{"user"}
	for _, userScope := range scopes {
		if fromMaster ||
			fromCanonScopes.Allowed(userScope.Name) ||
			GlobalScopes.Allowed(userScope.Name) {
			returnScopes = append(returnScopes, userScope.Name)
		}
	}

	httpWriteJSON(w, http.StatusOK, &auth.GetUserScopesResult{
		Name: username, Scopes: returnScopes})
}

func addUserScopesPOST(w http.ResponseWriter, r *http.Request) {
	fromToken, fromScopes := httpTokenInfo(r)
	if !fromScopes.IsService() {
		httpError(w, &ScopeRequiredError{"service"})
		return
	}
	if fromToken == nil {
		return // Shouldn't happen if we found the service scope.
	}
	fromMaster := fromScopes.IsMaster()

	fromClaims := fromToken.Claims.(jwt.MapClaims)
	var fromCanonScopes CanonScopes
	fromCanonScopes, _ = loadCanonScopes(fromClaims["canonScopes"])

	q := r.URL.Query()
	username := q.Get("user")
	var addScopes Scopes = parseCommaList(q.Get("scopes"))
	if username == "" || !addScopes.Valid() {
		httpError(w, &Error{http.StatusBadRequest, "missing parameter"})
		return
	}
	if len(addScopes) > 10 {
		httpError(w, &Error{http.StatusBadRequest, "too many scopes specified"})
		return
	}
	if !fromMaster {
		for _, scope := range addScopes {
			if !fromCanonScopes.Allowed(scope) {
				httpError(w, &Error{http.StatusForbidden,
					"canon scope denied"})
				return
			}
		}
	}

	tx := httpBeginDB(w, r)
	if tx == nil {
		return
	}
	defer tx.RollbackUnlessCommitted()

	user, err := tx.GetUserByName(r.Context(), username)
	if err != nil {
		httpError(w, &UserError{http.StatusBadRequest,
			"Invalid username"})
		return
	}

	scopes, err := tx.GetUserScopes(r.Context(), user.ID)
	if err != nil {
		httpError(w, err)
		return
	}

	now := time.Now()
	flags := ""
	if q.Get("auto") != "1" {
		flags += "e"
	}
	const maxMatchScopes = 10
	newScopesIndex := len(scopes)
	for _, scope := range addScopes {
		if !hasScope(scopes, scope) {
			if len(scopes) >= maxMatchScopes {
				cnt, cntScope := canonScopesCountScopes(fromCanonScopes, scopes, scope)
				if cnt >= maxMatchScopes {
					httpError(w, &Error{http.StatusBadRequest,
						"scope quota exceeded for this user (canon scope " + cntScope + ")"})
					return
				}
			}
			userScope := &store.UserScopeModel{UserID: user.ID, Name: scope,
				Created: now, Flags: flags}
			scopes = append(scopes, userScope)
		}
	}

	if len(scopes) > newScopesIndex {
		// Add the new scopes.
		for _, userScope := range scopes[newScopesIndex:] {
			err := tx.InsertUserScope(r.Context(), user.ID, userScope)
			if err != nil {
				httpError(w, err)
				return
			}
		}

		err := tx.Commit()
		if err != nil {
			httpError(w, err)
			return
		}
	}

	httpWriteOK(w)
}

// Ensure user doesn't have too many scopes, including sub scopes, for the canon scope.
// Finds which canon scope matches with scope, and counts how many scopes match it in scopes.
// If scope matches with multiple canon scopes, uses the one with the lowest count.
func canonScopesCountScopes(canonScopes CanonScopes, scopes []*store.UserScopeModel, scope string) (int, string) {
	lowestCount := 0
	lowestScope := ""
	for _, canonScope := range canonScopes {
		if CanonScopeAllowed(canonScope, scope) {
			count := 0
			for _, userScope := range scopes {
				if CanonScopeAllowed(canonScope, userScope.Name) {
					count++
				}
			}
			if count < lowestCount {
				lowestCount = count
				lowestScope = canonScope
			}
		}
	}
	return lowestCount, lowestScope
}

func hasScope(scopes []*store.UserScopeModel, scope string) bool {
	for _, x := range scopes {
		if x.Name == scope {
			return true
		}
	}
	return false
}

const defUsernamePattern = `^[a-zA-Z][a-zA-Z0-9-]{0,18}[a-zA-Z0-9]$`

var UsernameRegexp = regexp.MustCompile(defUsernamePattern)

func genPasswordAuth(password string) (string, error) {
	return bcryptsha256.Crypter.Hash(password)
}

// Returns true if password is correct.
func checkPasswordAuth(password string, auth string) bool {
	return bcryptsha256.Crypter.Verify(password, auth) == nil
}

func validatePassword(password string) error {
	//if len(password) < 6 {
	if utf8.RuneCountInString(password) < 6 {
		return errors.New("Please choose a longer password")
	}
	if len(password) > 1000 {
		return errors.New("Invalid password (too long)")
	}
	info := getStringInfo(password)
	if info&(stringControl|stringInvalid) != 0 {
		return errors.New("Invalid password (illegal characters)")
	}
	if len(password) < 8 && info&(stringSymbol|stringDigit|stringMulti) == 0 &&
		info&(stringLower|stringUpper) != (stringLower|stringUpper) {
		return errors.New("Please choose a more complex password (at least 8 characters or mixed case)")
	}
	if info == stringDigit { // all digits, such as "123456"
		return errors.New("Please choose a more complex password (add letters or symbols)")
	}
	if info == stringSymbol { // all ascii symbols, such as "!@#$%^&*"
		return errors.New("Please choose a more complex password (add letters or digits)")
	}
	lowerPassword := strings.ToLower(password)
	if lowerPassword == "password" || lowerPassword == "qwerty" ||
		lowerPassword == "sunshine" || lowerPassword == "iloveyou" ||
		lowerPassword == "princess" || lowerPassword == "admin" ||
		lowerPassword == "password1" || lowerPassword == "welcome" ||
		lowerPassword == "baseball" || lowerPassword == "dragon" ||
		lowerPassword == "login" || lowerPassword == "passw0rd" ||
		lowerPassword == "football" || lowerPassword == "monkey" ||
		lowerPassword == "abc123" || lowerPassword == "mustang" ||
		lowerPassword == "access" || lowerPassword == "shadow" ||
		lowerPassword == "master" || lowerPassword == "michael" {
		return errors.New("Please choose a more complex password (common password rejected)")
	}
	return nil
}

func validateEmail(email string) error {
	info := getStringInfo(email)
	if len(email) < 6 || len(email) > 254 ||
		info&(stringControl|stringInvalid) != 0 ||
		strings.ContainsAny(email, " <,;") ||
		strings.IndexByte(email, '@') == -1 ||
		strings.IndexByte(email, '.') == -1 {
		return errors.New("Invalid e-mail address")
	}
	return nil
}

func validateUsername(username string) error {
	if !UsernameRegexp.MatchString(username) || strings.Index(username, "--") != -1 {
		return errors.New("Invalid username; please use letters, numbers and dashes, and start with a letter")
	}
	return nil
}

const (
	stringInvalid = 1 << iota
	stringLower   // a-z
	stringUpper   // A-Z
	stringDigit   // 0-9
	stringControl // ascii
	stringSpace   // ' '
	stringSymbol  // ascii symbol or punct
	stringMulti   // utf8 multibyte
)

func getStringInfo(s string) int { // returns the string* bits above.
	result := 0
	for _, c := range s {
		if c == utf8.RuneError {
			result |= stringInvalid
		} else if c >= 'a' && c <= 'z' {
			result |= stringLower
		} else if c >= 'A' && c <= 'Z' {
			result |= stringUpper
		} else if c >= '0' && c <= '9' {
			result |= stringDigit
		} else if c < ' ' {
			result |= stringControl
		} else if c == ' ' {
			result |= stringSpace
		} else if c < 0x80 {
			result |= stringSymbol
		} else {
			result |= stringMulti
		}
	}
	return result
}
