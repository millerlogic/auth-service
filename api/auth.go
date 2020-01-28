// Copyright (C) 2020 Christopher E. Miller
//
// This API definition is under the MIT license: https://mit-license.org/

package auth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Auth struct {
	URL       string
	AuthToken string // either a service token string, user token string, or empty.
	Log       interface {
		Println(v ...interface{})
		Printf(format string, v ...interface{})
	}

	mx  sync.RWMutex
	key *rsa.PublicKey
}

type InvalidTokenError struct {
	*jwt.ValidationError
}

func (err *InvalidTokenError) Unwrap() error {
	return err.ValidationError
}

func (err *InvalidTokenError) Expired() bool {
	return err.Errors&jwt.ValidationErrorExpired != 0
}

// CallError is a generic API call error from a failed HTTP request.
type CallError struct {
	Msg            string
	HTTPStatus     string
	HTTPStatusCode int
	ScopeRequired  string
	IsUserError    bool
}

func (err *CallError) Error() string {
	if err == nil {
		return "OK"
	}
	return err.Msg
}

// NewCallError creates a *CallError from the HTTP Response, or nil if the status is 200.
// The body should not be read yet, this call reads the body if the result is not nil.
// The caller needs to close the body sometime after this call.
func NewCallError(resp *http.Response) *CallError {
	if resp.StatusCode == 200 {
		return nil
	}
	err := &CallError{}
	if strings.Index(resp.Header.Get("Content-Type"), "json") != -1 {
		var x map[string]interface{}
		err2 := json.NewDecoder(resp.Body).Decode(&x)
		if err2 != nil {
			err.Msg = "JSON response decode error for " + resp.Status
		} else {
			if m, _ := x["error"].(string); m != "" {
				err.Msg = m
			} else {
				err.Msg = "unknown JSON response for " + resp.Status
			}
			if x, _ := x["scopeRequired"].(string); x != "" {
				err.ScopeRequired = x
			}
			if x, _ := x["userError"].(bool); x {
				err.IsUserError = true
			}
		}
	} else {
		msgb := &bytes.Buffer{}
		const lim = 300
		_, err2 := msgb.ReadFrom(io.LimitReader(resp.Body, lim))
		if err2 != nil {
			err.Msg = "unable to read response for " + resp.Status + ": " + err2.Error()
		} else {
			if msgb.Len() == lim {
				msgb.WriteString("...")
			}
			err.Msg = msgb.String()
		}
	}
	err.HTTPStatus = resp.Status
	err.HTTPStatusCode = resp.StatusCode
	return err
}

// GetTokenScopes gets the Scopes from the Token.
// Only guaranteed to work on tokens returned by Auth.
func GetTokenScopes(tok *Token) Scopes {
	var scopes Scopes
	if claims, _ := tok.Claims.(jwt.MapClaims); claims != nil {
		if scopesStr, ok := claims["scopes"].(string); ok {
			scopes.UnmarshalText([]byte(scopesStr))
		}
	}
	return scopes
}

// GetToken reads tokenString, returns a validated *Token, or error.
// The error can be of type *InvalidTokenError, *CallError, *url.Error, or other.
func (auth *Auth) GetToken(ctx context.Context, tokenString string) (*Token, error) {
	key, err := auth.getKey(ctx)
	if err != nil {
		return nil, err
	}
	signMethod := "RS" + strconv.FormatInt(int64(key.Size()), 10)
	parser := jwt.Parser{
		ValidMethods: []string{signMethod},
	}
	tok, err := parser.Parse(tokenString, func(tok *Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		if verr, ok := err.(*jwt.ValidationError); ok {
			return nil, &InvalidTokenError{verr}
		}
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("unauthorized")
	}
	return tok, nil
}

var ErrNoToken = errors.New("no token")

// Authorization gets the token from the Authorization header, passes it to GetToken.
// Returns ErrNoToken if the expected token is not present.
func (auth *Auth) Authorization(r *http.Request) (*Token, error) {
	a := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(a) > len(prefix) && strings.EqualFold(prefix, a[:len(prefix)]) {
		tokenString := a[len(prefix):]
		return auth.GetToken(r.Context(), tokenString)
	}
	return nil, ErrNoToken
}

type LoginArgs struct {
	Duration time.Duration // optional
	Request  []string
	Demand   []string
	Allow    []string // optional
	Deny     []string // optional
	Username string
	Password string
	LoginBody
}

type LoginBody struct {
	ExchangeToken string `json:"exchange,omitempty"`
}

func (args LoginArgs) toQS() url.Values {
	v := url.Values{}
	if args.Duration != 0 {
		v.Set("duration", args.Duration.String())
	}
	if args.Request != nil {
		v.Set("request", strings.Join(args.Request, ","))
	}
	if args.Demand != nil {
		v.Set("demand", strings.Join(args.Demand, ","))
	}
	if args.Allow != nil {
		v.Set("allow", strings.Join(args.Allow, ","))
	}
	if args.Deny != nil {
		v.Set("deny", strings.Join(args.Deny, ","))
	}
	return v
}

func (auth *Auth) Login(ctx context.Context, args LoginArgs) (*TokenResult, error) {
	body := bytes.NewBuffer(nil)
	err := json.NewEncoder(body).Encode(&args.LoginBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		auth.url("/v1/login"+addQS(args.toQS())), body)
	if err != nil {
		return nil, err
	}

	if args.Username != "" || args.Password != "" {
		req.SetBasicAuth(args.Username, args.Password)
	}

	if auth.AuthToken != "" { // TODO: BUG: overwrites the basic login info above!
		req.Header.Set("Authorization", "Bearer "+auth.AuthToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	cerr := NewCallError(resp)
	if cerr != nil {
		return nil, cerr
	}

	var tokr TokenResult
	err = json.NewDecoder(resp.Body).Decode(&tokr)
	if err != nil {
		return nil, err
	}
	return &tokr, nil
}

type SignupArgs struct {
	NoPassword bool
	AnyEmail   bool
	SignupBody
}

type SignupBody struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (args SignupArgs) toQS() url.Values {
	v := url.Values{}
	if args.NoPassword {
		v.Set("no-password", "1")
	}
	if args.AnyEmail {
		v.Set("any-email", "1")
	}
	return v
}

func (auth *Auth) Signup(ctx context.Context, args SignupArgs) (*TokenResult, error) {
	body := bytes.NewBuffer(nil)
	err := json.NewEncoder(body).Encode(&args.SignupBody)
	if err != nil {
		return nil, err
	}
	var tokr TokenResult
	err = auth.reqToJSON(ctx, "POST", "/v1/signup"+addQS(args.toQS()), body, &tokr)
	if err != nil {
		return nil, err
	}
	return &tokr, nil
}

type CreateKeyArgs struct {
	Duration    time.Duration // optional
	Name        string        // optional
	Scopes      []string
	CanonScopes []string // optional
}

func (args CreateKeyArgs) toQS() url.Values {
	v := url.Values{}
	if args.Duration != 0 {
		v.Set("duration", args.Duration.String())
	}
	if args.Name != "" {
		v.Set("name", args.Name)
	}
	if args.Scopes != nil {
		v.Set("scopes", strings.Join(args.Scopes, ","))
	}
	if args.CanonScopes != nil {
		v.Set("canon-scopes", strings.Join(args.CanonScopes, ","))
	}
	return v
}

func (auth *Auth) CreateKey(ctx context.Context, args CreateKeyArgs) (*TokenResult, error) {
	var tokr TokenResult
	err := auth.reqToJSON(ctx, "POST", "/v1/create-key"+addQS(args.toQS()), empty, &tokr)
	if err != nil {
		return nil, err
	}
	return &tokr, nil
}

type ValidateArgs struct {
	_ byte
}

func (auth *Auth) Validate(ctx context.Context, args ValidateArgs) (*TokenResult, error) {
	var tokr TokenResult
	err := auth.reqToJSON(ctx, "GET", "/v1/validate", empty, &tokr)
	if err != nil {
		return nil, err
	}
	return &tokr, nil
}

type InvalidateArgs struct {
	_ byte
}

func (auth *Auth) Invalidate(ctx context.Context, args InvalidateArgs) error {
	resp, err := auth.req(ctx, "POST", "/v1/invalidate", empty)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

type UpdateUserArgs struct {
	UpdateUserBody
}

type UpdateUserBody struct {
	Updates map[string]interface{} `json:"updates"`
}

func (auth *Auth) UpdateUser(ctx context.Context, args UpdateUserArgs) error {
	body := bytes.NewBuffer(nil)
	err := json.NewEncoder(body).Encode(&args.UpdateUserBody)
	if err != nil {
		return err
	}
	resp, err := auth.req(ctx, "POST", "/v1/update-user", body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

type GetUserArgs struct {
	User string
}

func (args GetUserArgs) toQS() url.Values {
	v := url.Values{}
	v.Set("user", args.User)
	return v
}

func (auth *Auth) GetUser(ctx context.Context, args GetUserArgs) (*GetUserResult, error) {
	var gur GetUserResult
	err := auth.reqToJSON(ctx, "GET", "/v1/get-user"+addQS(args.toQS()), nil, &gur)
	if err != nil {
		return nil, err
	}
	return &gur, nil
}

type GetUserScopesArgs struct {
	User string
}

func (args GetUserScopesArgs) toQS() url.Values {
	v := url.Values{}
	v.Set("user", args.User)
	return v
}

func (auth *Auth) GetUserScopes(ctx context.Context, args GetUserScopesArgs) (*GetUserScopesResult, error) {
	var gusr GetUserScopesResult
	err := auth.reqToJSON(ctx, "GET", "/v1/get-user-scopes"+addQS(args.toQS()), nil, &gusr)
	if err != nil {
		return nil, err
	}
	return &gusr, nil
}

type AddUserScopesArgs struct {
	User   string
	Scopes []string
	Auto   bool
}

func (args AddUserScopesArgs) toQS() url.Values {
	v := url.Values{}
	v.Set("user", args.User)
	v.Set("scopes", strings.Join(args.Scopes, ","))
	if args.Auto {
		v.Set("auto", "1")
	}
	return v
}

func (auth *Auth) AddUserScopes(ctx context.Context, args AddUserScopesArgs) error {
	resp, err := auth.req(ctx, "POST", "/v1/add-user-scopes"+addQS(args.toQS()), empty)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// path is passed to auth.url to form a complete request URL.
// NewCallError is called on the response to generate an error,
// in which case the body is closed and the response is returned with the error.
// Another error type that can be returned is *url.Error which is an error from Client.Do.
func (auth *Auth) req(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, auth.url(path), nil)
	if err != nil {
		return nil, err
	}
	if auth.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+auth.AuthToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	cerr := NewCallError(resp)
	if cerr != nil {
		resp.Body.Close()
		return resp, cerr
	}
	return resp, nil
}

// decode the body JSON into v.
// see req for more info.
func (auth *Auth) reqToJSON(ctx context.Context, method, path string, body io.Reader, v interface{}) error {
	resp, err := auth.req(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

func (auth *Auth) url(path string) string {
	return strings.TrimRight(auth.URL, "/") + path
}

// PublicKey gets the public key from the auth service.
func (auth *Auth) PublicKey(ctx context.Context) (interface{}, error) {
	return auth.getKey(ctx)
}

func (auth *Auth) getKey(ctx context.Context) (*rsa.PublicKey, error) {
	key := auth.getKeyRead()
	if key != nil {
		return key, nil
	}
	if auth.Log != nil {
		auth.Log.Println("Get public key")
	}
	key, err := auth.getKeyWrite(ctx)
	if err != nil {
		if auth.Log != nil {
			auth.Log.Printf("Error: %v", err)
		}
		return nil, err
	}
	return key, nil
}

func (auth *Auth) getKeyRead() *rsa.PublicKey {
	auth.mx.RLock()
	key := auth.key
	auth.mx.RUnlock()
	return key
}

func (auth *Auth) getKeyWrite(ctx context.Context) (*rsa.PublicKey, error) {
	auth.mx.Lock()
	defer auth.mx.Unlock()
	key := auth.key
	if key == nil {
		resp, err := auth.req(ctx, "GET", "/v1/pubkey", nil)
		if err != nil {
			return nil, err
		}
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
		p, _ := pem.Decode(b)
		okey, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			return nil, err
		}
		if xkey, _ := okey.(*rsa.PublicKey); xkey != nil {
			key = xkey
		} else {
			return nil, errors.New("wrong key type")
		}
	}
	return key, nil
}

func addQS(v url.Values) string {
	if v == nil || len(v) == 0 {
		return ""
	}
	return "?" + v.Encode()
}

var empty = http.NoBody
