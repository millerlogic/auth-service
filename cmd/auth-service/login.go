// Copyright (C) 2020 Christopher E. Miller
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/millerlogic/auth-service/store"
	"github.com/ulule/limiter/v3"
	limiter_memory "github.com/ulule/limiter/v3/drivers/store/memory"
)

var Realm = "auth-service"

// TODO: don't use in-memory limit store.
var loginRateStore = limiter_memory.NewStoreWithOptions(limiter.StoreOptions{
	Prefix:          "",
	CleanUpInterval: limiter.DefaultCleanUpInterval,
})

var loginIPRate = limiter.Rate{
	Period: 60 * time.Second,
	Limit:  6,
}
var loginIPLimiter = limiter.New(loginRateStore, loginIPRate)

// This protects a single user from being brute forced from various locations.
var loginUserRate = limiter.Rate{
	Period: 120 * time.Second,
	Limit:  12,
}
var loginUserLimiter = limiter.New(loginRateStore, loginUserRate)

func loginPOST(w http.ResponseWriter, r *http.Request) {
	fromToken, fromScopes := httpTokenInfo(r)

	if fromScopes.IsService() {
		httpError(w, &Error{http.StatusBadRequest,
			"service must use login-as"})
		return
	}

	fromExchangeToken := fromScopes.Has("user_exchange_token") // user exchange tok

	var username, password string
	if fromExchangeToken {
		username, _ = fromToken.Claims.(jwt.MapClaims)["sub"].(string)
		if username == "" {
			httpError(w, errors.New("empty username from exchange token"))
			return
		}
	} else {
		username, password, _ = r.BasicAuth()
		if username == "" || password == "" {
			w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, Realm))
			httpError(w, &Error{http.StatusUnauthorized, "invalid auth"})
			return
		}
	}

	loginCommonReq(w, r, userLoginCommonInfo{
		username:          username,
		password:          password,
		fromToken:         fromToken,
		fromScopes:        fromScopes,
		fromExchangeToken: fromExchangeToken,
	})
}

// login as user, for granted service.
func loginAsPOST(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		User       string `json:"user"`
		Password   string `json:"password"`
		NoPassword bool   `json:"noPassword"`
	}
	if !httpGetJSON(w, r, &payload) {
		return
	}

	fromToken, fromScopes := httpTokenInfo(r)

	if !fromScopes.IsService() {
		httpError(w, &Error{http.StatusBadRequest,
			"login-as reserved for service"})
		return
	}

	if !fromScopes.Has("user_login_as") {
		httpError(w, &ScopeRequiredError{"user_login_as"})
		return
	}

	loginCommonReq(w, r, userLoginCommonInfo{
		username:           payload.User,
		password:           payload.Password,
		fromToken:          fromToken,
		fromScopes:         fromScopes,
		fromServiceLoginAs: true,
		noPassword:         payload.NoPassword,
	})
}

type userLoginCommonInfo struct {
	username           string
	password           string
	fromToken          *jwt.Token
	fromScopes         Scopes
	fromExchangeToken  bool
	fromServiceLoginAs bool
	noPassword         bool
}

// Note: fromToken and fromScopes are different depending on fromServiceLoginAs.
func loginCommonReq(w http.ResponseWriter, r *http.Request, info userLoginCommonInfo) {
	fromServiceLoginOverride := false
	if info.fromServiceLoginAs {
		fromServiceLoginOverride = info.fromScopes.Has("user_login_override")
	}

	usernameLower := strings.ToLower(info.username)

	remoteIP := limiter.GetIP(r, limiter.Options{
		TrustForwardHeader: info.fromScopes.Has("login_proxy"),
	})

	// IP limiter:
	limitipkey := maskIP(remoteIP).String()
	//log.Printf("ctx.Request.RemoteAddr='%v' - limitipkey='%v'\n", ctx.Request.RemoteAddr, limitipkey)
	limitIPCtx, err := loginIPLimiter.Get(r.Context(), limitipkey)
	if err != nil {
		log.Printf("Login IP limiter error: %s", err)
		httpError(w, &Error{http.StatusInternalServerError,
			http.StatusText(http.StatusInternalServerError)})
		return
	}
	w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(limitIPCtx.Limit, 10))
	w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(limitIPCtx.Remaining, 10))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(limitIPCtx.Reset, 10))

	// User limiter:
	// This one is more stealthy, but is harder to hit.
	limituserkey := usernameLower
	limitUserCtx, err := loginUserLimiter.Get(r.Context(), limituserkey)
	if err != nil {
		log.Printf("Login User limiter error: %s", err)
		httpError(w, &Error{http.StatusInternalServerError,
			http.StatusText(http.StatusInternalServerError)})
		return
	}

	// If either limits hit:
	// Be sure to do this after updating all limits.
	if limitIPCtx.Reached {
		httpError(w, &UserError{http.StatusTooManyRequests,
			"Rate limit exceeded"})
		return
	}
	if limitUserCtx.Reached {
		// Fake this one as generally unauthorized;
		// also because the X-RateLimit-* headers would be "wrong" otherwise.
		log.Println("Login User limiter; rate limit exceeded; RemoteAddr=", r.RemoteAddr)
		httpError(w, &Error{http.StatusUnauthorized,
			http.StatusText(http.StatusUnauthorized)})
		return
	}

	tx := httpBeginDB(w, r)
	if tx == nil {
		return
	}
	defer tx.RollbackUnlessCommitted()

	q := r.URL.Query()
	lttDuration, err := time.ParseDuration(q.Get("duration"))
	if err != nil {
		lttDuration = 24 * time.Hour
	}

	var fromTCode float64
	var requestScopes []string
	var demandScopes []string
	var allowScopes Scopes
	var denyScopes Scopes

	if info.fromExchangeToken {
		claims := info.fromToken.Claims.(jwt.MapClaims)
		fromTCode, _ = claims["tcode"].(float64)
	}

	if info.fromServiceLoginAs || info.fromExchangeToken {
		claims := info.fromToken.Claims.(jwt.MapClaims)
		allowScopes, _ = loadScopes(claims["allow"])
		if q.Get("allow") != "" {
			httpError(w, &Error{http.StatusBadRequest,
				"do not specify allow querystring when using token"})
			return
		}
		denyScopes, _ = loadScopes(claims["deny"])
		denyScopes = append(denyScopes, parseCommaList(q.Get("deny"))...)
	} else {
		allowScopes = parseCommaList(q.Get("allow"))
		denyScopes = parseCommaList(q.Get("deny"))
	}

	//requestScopes = parseCommaList(q.Get("request"))
	if x := q["request"]; len(x) > 0 {
		requestScopes = parseCommaList(x[0])
	} else {
		// If no request param, request the allowed scopes.
		requestScopes = allowScopes
	}
	demandScopes = parseCommaList(q.Get("demand"))

	token, _, ltt, err := UserLogin(r.Context(), tx, UserLoginInfo{
		Username:                 info.username,
		Password:                 info.password,
		RequestScopes:            requestScopes,
		DemandScopes:             demandScopes,
		AllowScopes:              allowScopes,
		DenyScopes:               denyScopes,
		IP:                       remoteIP,
		FromTokenCode:            fromTCode,
		LTTDuration:              lttDuration,
		FromExchangeToken:        info.fromExchangeToken,
		FromServiceLoginAs:       info.fromServiceLoginAs,
		FromServiceLoginOverride: fromServiceLoginOverride,
		NoPassword:               info.noPassword,
	})
	if err != nil {
		w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, Realm))
		httpError(w, err)
		return
	}

	// Sign token by private key
	privateKey := r.Context().Value(privkeyCtxKey).(*rsa.PrivateKey)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		httpError(w, err)
		return
	}
	token.Raw = signedToken
	token.Valid = true

	lttSignedToken := ""
	if ltt != nil {
		lttSignedToken, err = ltt.SignedString(privateKey)
		if err != nil {
			httpError(w, err)
			return
		}
		ltt.Raw = lttSignedToken
		ltt.Valid = true
	}

	err = tx.Commit()
	if err != nil {
		httpError(w, err)
		return
	}

	httpWriteJSON(w, http.StatusOK, getTokenResult(token, lttSignedToken))
}

func parseCommaList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' })
}

type UserLoginInfo struct {
	Username                 string
	Password                 string
	RequestScopes            Scopes
	DemandScopes             Scopes
	AllowScopes              Scopes
	DenyScopes               Scopes
	IP                       net.IP
	FromTokenCode            float64       // 0 if no token; needed for FromExchangeToken.
	LTTDuration              time.Duration // LTT output duration, 0 for no LTT at all.
	FromExchangeToken        bool          // LTT input; ignores Password.
	FromServiceLoginAs       bool
	FromServiceLoginOverride bool // allows service to login as user without user's password.
	NoPassword               bool // be explicit about password bypass (only if login override)
}

// Caller needs to commit the transaction.
// info.FromExchangeToken being set means it is a LTT, and Password is not checked!
// The second *jwt.Token returned is the new LTT, which can be nil when not applicable!
func UserLogin(ctx context.Context, tx store.DBTx, info UserLoginInfo) (*jwt.Token, Scopes, *jwt.Token, error) {
	now := time.Now()

	if info.FromServiceLoginOverride && !info.FromServiceLoginAs {
		panic("not ok: info.FromServiceLoginOverride && !info.FromServiceLoginAs")
	}
	if info.FromExchangeToken && info.FromServiceLoginAs {
		panic("not ok: info.FromExchangeToken && info.FromServiceLoginAs")
	}
	if info.NoPassword && !info.FromServiceLoginOverride {
		panic("not ok: info.NoPassword && !info.FromServiceLoginOverride")
	}

	if info.FromServiceLoginAs {
		x := "with password"
		if info.FromServiceLoginOverride && info.NoPassword {
			x = "service override"
		}
		log.Printf("* Logging into %s from %s using login-as (%s)",
			info.Username, info.IP, x)
	} else if info.FromExchangeToken {
		log.Printf("* Logging into %s from %s using exchange token",
			info.Username, info.IP)
	} else {
		log.Printf("* Logging into %s from %s using password",
			info.Username, info.IP)
	}

	// Login:
	user, err := tx.GetUserByName(ctx, info.Username)
	errInvalidUserPw := &UserError{http.StatusUnauthorized,
		"Invalid username or password"}
	if err != nil {
		return nil, nil, nil, errInvalidUserPw
	}
	if !info.FromExchangeToken && (!info.FromServiceLoginOverride || !info.NoPassword) {
		if !checkPasswordAuth(info.Password, user.Auth) {
			return nil, nil, nil, errInvalidUserPw
		}
	}

	if info.FromExchangeToken {
		// Confirm the tcode (TokenCode) is valid on the LTT,
		// This is the way to invalidate exchange tokens.
		if info.FromTokenCode != float64(user.TokenCode) {
			return nil, nil, nil, &Error{http.StatusUnauthorized, "invalid token"}
		}
	}

	if strings.IndexByte(user.Flags, 's') != -1 {
		// Suspended user account.
		return nil, nil, nil, &UserError{http.StatusUnauthorized,
			"Unable to login"}
	}
	if strings.IndexByte(user.Flags, 'd') != -1 {
		// Deleted user account.
		return nil, nil, nil, errInvalidUserPw
	}

	user.LastIP = info.IP.String()
	user.LastLogin = now

	err = tx.UpdateUser(ctx, user, "LastIP", "LastLogin")
	if err != nil {
		return nil, nil, nil, err
	}

	log.Printf("* Logged into %s from %s successfully!", info.Username, info.IP)

	expiresAt := now.Add(15 * time.Minute)
	var strScopes Scopes

	strScopes = append(strScopes, "user") // it's a user token

	if strings.IndexByte(user.Flags, 'c') != -1 {
		strScopes = append(strScopes, "user_confirmed")
	} else {
		// Usually we don't have two scopes to mean the opposite,
		// but in this case it's more for the shaming effect!
		strScopes = append(strScopes, "user_unconfirmed")
	}

	requestScopesMap := make(map[string]bool, len(info.RequestScopes))
	for _, x := range info.RequestScopes {
		if x == "user_edit" {
			return nil, nil, nil, &Error{http.StatusUnauthorized,
				"cannot request user_edit scope, must demand"}
		}
		requestScopesMap[x] = true
	}

	editUser := false
	demandScopesMap := make(map[string]bool, len(info.DemandScopes))
	for _, x := range info.DemandScopes {
		if x == "user_edit" {
			editUser = true
		}
		demandScopesMap[x] = true
	}

	var allowScopesMap map[string]bool // nil if no allows!
	if info.AllowScopes != nil {
		allowScopesMap = make(map[string]bool, len(info.AllowScopes))
		for _, x := range info.AllowScopes {
			allowScopesMap[x] = true
		}
	}

	denyScopesMap := make(map[string]bool, len(info.DenyScopes))
	for _, x := range info.DenyScopes {
		denyScopesMap[x] = true
	}

	if editUser {
		// user_edit scope gets special handling.
		if info.FromExchangeToken || info.FromServiceLoginAs {
			// An exchange token can't create an edit token.
			return nil, nil, nil, &Error{http.StatusUnauthorized, "denied"}
		}
		if len(requestScopesMap)+len(demandScopesMap) != 1 || len(denyScopesMap) != 0 {
			return nil, nil, nil, &Error{http.StatusUnauthorized,
				"invalid use of user_edit scope"}
		}
		strScopes = append(strScopes, "user_edit")
		expiresAt = now.Add(5 * time.Minute)
	} else {
		scopes, err := tx.GetUserScopes(ctx, user.ID)
		if err != nil {
			log.Printf("ERROR can't get user scopes: %v", err)
		}
		for _, scope := range scopes {
			if requestScopesMap[scope.Name] || demandScopesMap[scope.Name] ||
				strings.IndexByte(scope.Flags, 'e') == -1 {
				if (allowScopesMap == nil || allowScopesMap[scope.Name]) &&
					!denyScopesMap[scope.Name] {
					strScopes = append(strScopes, scope.Name)
					delete(demandScopesMap, scope.Name)
				}
			}
		}
		if len(demandScopesMap) != 0 {
			// Note: this can happen if demand and deny have the same scope.
			return nil, nil, nil, &Error{http.StatusUnauthorized,
				"demand claims failed"}
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"iat":    now.Unix(),       // when the token was issued/created (now)
		"exp":    expiresAt.Unix(), // time when the token will expire
		"sub":    info.Username,    // the subject/principal is whom the token is about
		"scopes": strScopes,
		//"jti":    uuid.Must(uuid.NewV4()).String(), // a unique identifier for the token
		"id":    user.ID,
		"tcode": user.TokenCode,
	})

	var ltt *jwt.Token
	wantLTT := !editUser &&
		!info.FromExchangeToken &&
		!info.FromServiceLoginAs &&
		info.LTTDuration >= time.Second
	if wantLTT {
		lttExpiresAt := now.Add(info.LTTDuration)
		var lttScopes Scopes = []string{"user_exchange_token"}
		lttClaims := jwt.MapClaims{
			"iat":    now.Unix(),          // when the token was issued/created (now)
			"exp":    lttExpiresAt.Unix(), // time when the token will expire
			"sub":    info.Username,       // the subject/principal is whom the token is about
			"scopes": lttScopes,
			//"jti":    uuid.Must(uuid.NewV4()).String(), // a unique identifier for the token
			"id":    user.ID,
			"tcode": user.TokenCode,
		}
		if info.AllowScopes != nil {
			lttClaims["allow"] = info.AllowScopes
		}
		if len(info.DenyScopes) != 0 {
			lttClaims["deny"] = info.DenyScopes
		}
		ltt = jwt.NewWithClaims(jwt.SigningMethodRS512, lttClaims)
	}

	return token, strScopes, ltt, err
}
