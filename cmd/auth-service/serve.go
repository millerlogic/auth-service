// Copyright (C) 2020 Christopher E. Miller
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth"
	auth "github.com/millerlogic/auth-service/api"
	"github.com/millerlogic/auth-service/store"
)

type AuthArgs struct {
	DB              store.DB
	PrivateKey      *rsa.PrivateKey
	Throttle        int
	Timeout         time.Duration
	UsernamePattern string // empty to use default
	ForwardIPAll    bool
}

func newAuthHandler(args AuthArgs) http.Handler {
	if args.DB == nil {
		panic("nil DB")
	}
	if args.PrivateKey == nil {
		panic("nil PrivateKey")
	}

	if args.UsernamePattern != "" {
		UsernameRegexp = regexp.MustCompile(args.UsernamePattern)
	}

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	if args.ForwardIPAll {
		r.Use(middleware.RealIP)
	}
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.GetHead)
	if args.Throttle > 0 {
		throttleTimeout := 5 * time.Second
		if args.Timeout < throttleTimeout && args.Timeout > 0 {
			throttleTimeout = args.Timeout
		}
		r.Use(middleware.ThrottleBacklog(args.Throttle,
			args.Throttle/2+args.Throttle%2, throttleTimeout))
	}
	if args.Timeout > 0 {
		r.Use(middleware.Timeout(args.Timeout))
	}

	// Add middleware for common context vars:
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, dbsessCtxKey, args.DB.NewSession())
			ctx = context.WithValue(ctx, pubkeyCtxKey, &args.PrivateKey.PublicKey)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	// Validate the jwt if provided, but take no action on it.
	tokenAuth := jwtauth.New("RS512", args.PrivateKey, &args.PrivateKey.PublicKey)
	//r.Use(jwtauth.Verifier(tokenAuth))
	r.Use(func(next http.Handler) http.Handler {
		return jwtauth.Verify(tokenAuth, jwtauth.TokenFromHeader)(next)
	})

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/v1/", http.StatusTemporaryRedirect)
	})

	r.Route("/v1", func(r chi.Router) {

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			httpWriteOK(w)
		})

		r.Get("/pubkey", func(w http.ResponseWriter, r *http.Request) {
			bytes, err := x509.MarshalPKIXPublicKey(&args.PrivateKey.PublicKey)
			if err != nil {
				httpError(w, err)
				return
			}
			err = pem.Encode(w, &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: bytes,
			})
			if err != nil {
				httpError(w, err)
				return
			}
		})

		// Routes having access to the private key:
		r.Group(func(r chi.Router) {
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ctx := r.Context()
					ctx = context.WithValue(ctx, privkeyCtxKey, args.PrivateKey)
					next.ServeHTTP(w, r.WithContext(ctx))
				})
			})

			r.Post("/login", loginPOST)
			r.Post("/login-as", loginAsPOST)

			r.Post("/signup", signupPOST)

			r.Post("/create-key", createKeyPOST)
		})

		// Routes which are protected, the user must be logged in:
		r.Group(func(r chi.Router) {
			// Middleware to ensure valid jwt!
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ctx := r.Context()
					err, _ := ctx.Value(jwtauth.ErrorCtxKey).(error)
					if err != nil {
						w.Header().Set(contentTypeHeader, jsonType)
						w.WriteHeader(http.StatusUnauthorized)
						switch err {
						case jwtauth.ErrNoTokenFound:
							w.Write([]byte(`{"error":"no token found"}`))
						default:
							log.Printf("INFO jwtauth error from %s: %v", r.RemoteAddr, err)
							w.Write([]byte(`{"error":"invalid token"}`))
						}
						return
					}
					_, scopes := httpTokenInfo(r)
					if !scopes.IsUser() && !scopes.IsService() {
						httpError(w, &Error{http.StatusForbidden, "wrong token type"})
						return
					}
					next.ServeHTTP(w, r)
				})
			})

			r.Get("/validate", func(w http.ResponseWriter, r *http.Request) {
				httpWriteJSON(w, http.StatusOK, httpTokenResult(r))
			}) // ensures signed properly and not expired.

			r.Post("/invalidate", invalidatePOST)

			r.Post("/update-user", updateUserPOST)

			r.Get("/get-user", getUserGET)

			r.Get("/get-user-scopes", getUserScopesGET)

			r.Post("/add-user-scopes", addUserScopesPOST)
		})

	})

	return r
}

const contentTypeHeader = "Content-Type"
const jsonType = "application/json"

type ctxKey struct{ name string }

func (ck ctxKey) String() string {
	return ck.name
}

var dbsessCtxKey = &ctxKey{"DBSession"}
var pubkeyCtxKey = &ctxKey{"PublicKey"}
var privkeyCtxKey = &ctxKey{"PrivateKey"}

var jwtTokenCtxKey = jwtauth.TokenCtxKey

func getDBSession(ctx context.Context) store.DBSession {
	x, _ := ctx.Value(dbsessCtxKey).(store.DBSession)
	return x
}

func beginDB(ctx context.Context) (store.DBTx, error) {
	sess := getDBSession(ctx)
	if sess == nil {
		return nil, errors.New("no DB on context?!")
	}
	return sess.Begin(ctx)
}

// Returns nil if not opened.
func httpBeginDB(w http.ResponseWriter, r *http.Request) store.DBTx {
	tx, err := beginDB(r.Context())
	if err != nil {
		log.Printf("ERROR unable to open db: %v", err)
		httpError(w, &UserError{http.StatusInternalServerError,
			"Unable to open database, you know how it is"})
		return nil
	}
	return tx
}

var ipv4mask = net.CIDRMask(32, 32)
var ipv6mask = net.CIDRMask(64, 128)

func maskIP(ip net.IP) net.IP {
	if ip.To4() != nil {
		return ip.Mask(ipv4mask)
	}
	if ip.To16() != nil {
		return ip.Mask(ipv6mask)
	}
	return ip
}

type tokenResult = auth.TokenResult

// lttTokenString is the LTT signed token string, or empty if none.
func getTokenResult(token *jwt.Token, lttTokenString string) tokenResult {
	var result tokenResult
	if token != nil && token.Valid && token.Raw != "" {
		claims := token.Claims.(jwt.MapClaims)
		if claims != nil {
			result.Valid = true
			result.Token = token.Raw
			result.Name, _ = claims["sub"].(string)
			result.Scopes, _ = loadScopes(claims["scopes"])
			//result.CanonScopes, _ = loadCanonScopes(claims["canonScopes"])
			result.Exchange = lttTokenString
		}
	}
	if result.Scopes == nil {
		result.Scopes = []string{} // don't use null
	}
	return result
}

func httpTokenResult(r *http.Request) tokenResult {
	token, _ := httpTokenInfo(r)
	return getTokenResult(token, "")
}

// Safe to call even if no token was part of the request.
// Returned token can be nil, scopes can be empty.
func httpTokenInfo(r *http.Request) (token *jwt.Token, scopes Scopes) {
	err, _ := r.Context().Value(jwtauth.ErrorCtxKey).(error)
	if err != nil {
		if err != jwtauth.ErrNoTokenFound {
			log.Printf("INFO jwtauth error from %s: %v", r.RemoteAddr, err)
		}
	} else { // Only trust token if no jwtauth error!
		token, _ = r.Context().Value(jwtauth.TokenCtxKey).(*jwt.Token)
		if token != nil {
			claims := token.Claims.(jwt.MapClaims)
			scopes, _ = loadScopes(claims["scopes"])
			/*if scopes.Valid() {
				log.Printf("INFO %s has token with scopes: %s", r.RemoteAddr, scopes)
			}*/
		}
	}
	return
}

func loadScopes(x interface{}) (Scopes, bool) {
	switch a := x.(type) {
	case string:
		var scopes Scopes
		err := scopes.UnmarshalText([]byte(a))
		return scopes, err == nil
	case Scopes:
		return a, true
	case CanonScopes:
		return Scopes(a), true
	}
	return nil, false
}

func loadCanonScopes(x interface{}) (CanonScopes, bool) {
	a, b := loadScopes(x)
	return CanonScopes(a), b
}

// does not validate the token, the caller is expected to do that already!
// however, it does check the token code.
func userFromToken(ctx context.Context, token *jwt.Token, tx store.DBTx) (*store.UserModel, error) {
	claims := token.Claims.(jwt.MapClaims)
	if claims != nil {
		username, _ := claims["sub"].(string)
		if username != "" {
			user, err := tx.GetUserByName(ctx, username)
			if err != nil {
				if err == store.ErrNotFound {
					return nil, &Error{http.StatusUnauthorized, "no such user"}
				}
				return nil, err
			}
			tcode, _ := claims["tcode"].(float64)
			if tcode != float64(user.TokenCode) {
				log.Println("user used token with invalidated tcode")
				// Don't give too much info here, just look like a normal token issue:
				return nil, &Error{http.StatusUnauthorized, "invalid token"}
			}
			return user, nil
		}
	}
	return nil, errors.New("no claims")
}

// Returns nil user if an error is written.
func httpUser(w http.ResponseWriter, r *http.Request, tx store.DBTx) (*store.UserModel, *jwt.Token, Scopes) {
	token, scopes := httpTokenInfo(r)
	if token == nil {
		httpError(w, &Error{http.StatusUnauthorized, "invalid token"})
		return nil, nil, nil
	} else {
		user, err := userFromToken(r.Context(), token, tx)
		if err != nil {
			httpError(w, err)
			return nil, nil, nil
		}
		return user, token, scopes
	}
}

type Error struct {
	Code int    `json:"-"`
	Msg  string `json:"error"`
}

func (err *Error) Error() string {
	return err.Msg
}

type UserError struct {
	Code int    `json:"-"`
	Msg  string `json:"error"`
}

func (err *UserError) Error() string {
	return err.Msg
}

type ScopeRequiredError struct {
	Scope string `json:"scopeRequired"`
}

func (err *ScopeRequiredError) Error() string {
	return "denied"
}

func httpWriteJSON(w http.ResponseWriter, code int, x interface{}) {
	b, err := json.Marshal(x)
	if err != nil {
		log.Printf("ERROR JSON marshal error: %v", err)
		b = []byte(`{"error":"JSON marshal error"}`)
	}
	w.Header().Set(contentTypeHeader, jsonType)
	w.WriteHeader(code)
	w.Write(b)
}

func httpWriteOK(w http.ResponseWriter) {
	//httpWriteJSON(w, http.StatusOK, json.RawMessage(`{}`))
	w.Header().Set(contentTypeHeader, jsonType)
	w.Write([]byte(`{}`))
}

func httpError(w http.ResponseWriter, err error) {
	switch err := err.(type) {
	case *Error:
		httpWriteJSON(w, err.Code, err)
	case *ScopeRequiredError:
		httpWriteJSON(w, http.StatusForbidden, &struct {
			Msg string `json:"error"`
			*ScopeRequiredError
		}{err.Error(), err})
	case *UserError:
		httpWriteJSON(w, err.Code, &struct {
			*UserError
			IsUserError bool `json:"userError"`
		}{err, true})
	default:
		log.Printf("ERROR %v", err)
		uerr := &Error{http.StatusInternalServerError,
			http.StatusText(http.StatusInternalServerError)}
		httpWriteJSON(w, uerr.Code, uerr)
	}
}

func httpGetJSON(w http.ResponseWriter, r *http.Request, dest interface{}) bool {
	const limit = 16 * 1024
	//b, err := ioutil.ReadAll(io.LimitReader(r.Body, limit))
	b, err := ioutil.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	r.Body.Close()
	if err != nil {
		//httpWriteError(w, http.StatusBadRequest, Error{"request body error"})
		// http.MaxBytesReader already sends the error to the client...
		return false
	}
	if len(b) == 0 {
		// Explicitly treating empty body as a valid empty object.
		// This is so that a body of only optional fields doesn't need to be specified.
		return true
	}
	err = json.Unmarshal(b, dest)
	if err != nil {
		//log.Print(err)
		httpError(w, &Error{http.StatusBadRequest, "JSON unmarshal error"})
		return false
	}
	return true
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
