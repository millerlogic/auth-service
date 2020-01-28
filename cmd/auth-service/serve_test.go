package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func init() {
	SignupIPRateLimit.Limit = 100
	SignupRateLimit.Limit = 100
}

func TestServeBasic(t *testing.T) {
	handler, _ := newTestAuth()

	t.Run("v1", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusOK)
	})

	t.Run("nothing", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/nothing", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusNotFound)
	})

	t.Run("pubkey", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/pubkey", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		if bytes.Index(ensureResp(t, resp, http.StatusOK),
			[]byte("END PUBLIC KEY")) == -1 {
			t.Error("did not find pubkey")
		}
	})

	t.Run("validate", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/validate", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusUnauthorized)
	})

	t.Run("login", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/login", http.NoBody)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusUnauthorized)
	})

	t.Run("signup", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/signup", http.NoBody)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusBadRequest)
	})

	t.Run("create-key", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/create-key", http.NoBody)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusForbidden)
	})

	t.Run("invalidate", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/invalidate", http.NoBody)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusUnauthorized)
	})

	t.Run("get-user-scopes", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/get-user-scopes", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusUnauthorized)
	})

	t.Run("add-user-scopes", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/add-user-scopes", http.NoBody)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusUnauthorized)
	})

}

func TestServeSignup(t *testing.T) {
	handler, _ := newTestAuth()

	t.Run("signup f$ - bad username", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/signup", bytes.NewBufferString(`{
			"username": "f$",
			"email": "foo@bar.baz",
			"password": "asdf$1234"
		}`))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusBadRequest)
	})

	t.Run("signup foo - bad email", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/signup", bytes.NewBufferString(`{
			"username": "foo",
			"email": "foo-email",
			"password": "asdf$1234"
		}`))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusBadRequest)
	})

	t.Run("signup foo - ok", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/signup", bytes.NewBufferString(`{
			"username": "foo",
			"email": "foo@bar.baz",
			"password": "asdf$1234"
		}`))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusOK, "token", "name")
	})

	t.Run("signup foo - taken", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/signup", bytes.NewBufferString(`{
			"username": "foo",
			"email": "foo@bar.baz",
			"password": "asdf$1234"
		}`))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusUnauthorized)
	})

}

func TestServeLogin(t *testing.T) {
	handler, _ := newTestAuth()

	exchgtok := ""
	t.Run("signup foo", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/signup", bytes.NewBufferString(`{
			"username": "foo",
			"email": "foo@bar.baz",
			"password": "asdf$1234"
		}`))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		bytes := ensureResp(t, resp, http.StatusOK, "token", "name", "scopes", "exchange")
		var x struct {
			//Token string `json:"token"`
			Exchange string `json:"exchange"`
		}
		json.Unmarshal(bytes, &x)
		exchgtok = x.Exchange
	})

	t.Run("login foo - wrong pw", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/login", http.NoBody)
		r.SetBasicAuth("foo", "asdf")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusUnauthorized)
	})

	edittok := ""
	t.Run("login foo - ok, get edit token", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/login?demand=user_edit", http.NoBody)
		r.SetBasicAuth("foo", "asdf$1234")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		bytes := ensureResp(t, resp, http.StatusOK, "token", "name", "scopes")
		var x struct {
			Token string `json:"token"`
		}
		json.Unmarshal(bytes, &x)
		edittok = x.Token
	})

	tok := ""
	t.Run("login foo - using LTT", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/login", http.NoBody)
		//t.Logf("exchgtok = %s", exchgtok)
		r.Header.Set("Authorization", "Bearer "+exchgtok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		bytes := ensureResp(t, resp, http.StatusOK, "token", "name", "scopes")
		var x struct {
			Token string `json:"token"`
		}
		json.Unmarshal(bytes, &x)
		tok = x.Token
	})

	t.Run("invalidate foo LTT - fail not edit token", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/invalidate", http.NoBody)
		//t.Logf("tok = %s", tok)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusForbidden)
	})

	t.Run("invalidate foo LTT - ok", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/invalidate", http.NoBody)
		//t.Logf("edittok = %s", edittok)
		r.Header.Set("Authorization", "Bearer "+edittok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusOK)
	})

	t.Run("login foo - fail using invalidated LTT", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/login", http.NoBody)
		//t.Logf("exchgtok = %s", exchgtok)
		r.Header.Set("Authorization", "Bearer "+exchgtok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusUnauthorized)
	})
}

func TestServeUser(t *testing.T) {
	handler, _ := newTestAuth()

	tok := ""
	exchgtok := ""
	t.Run("signup foo", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/signup", bytes.NewBufferString(`{
			"username": "foo",
			"email": "foo@bar.baz",
			"password": "asdf$1234"
		}`))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		bytes := ensureResp(t, resp, http.StatusOK, "token", "name", "scopes", "exchange")
		var x struct {
			Token    string `json:"token"`
			Exchange string `json:"exchange"`
		}
		json.Unmarshal(bytes, &x)
		tok = x.Token
		exchgtok = x.Exchange
	})

	t.Run("get user - LTT fail", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/get-user", nil)
		r.Header.Set("Authorization", "Bearer "+exchgtok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusForbidden)
	})

	t.Run("get user - ok", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/get-user", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusOK, "id", "name", "email", "scopes")
	})
}

func TestServeService(t *testing.T) {
	handler, privateKey := newTestAuth()

	t.Run("signup foo", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/signup", bytes.NewBufferString(`{
			"username": "foo",
			"email": "foo@bar.baz",
			"password": "asdf$1234"
		}`))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusOK, "token", "name")
	})

	masterToken, err := newMasterToken(time.Minute, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	servicetok := ""
	t.Run("create service token from master", func(t *testing.T) {
		r := httptest.NewRequest("POST",
			"/v1/create-key?name=stuffer&canon-scopes=stuff,stuff2",
			http.NoBody)
		//t.Logf("Master = %s", masterToken.Raw)
		r.Header.Set("Authorization", "Bearer "+masterToken.Raw)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		bytes := ensureResp(t, resp, http.StatusOK, "token", "name")
		var x struct {
			Token string `json:"token"`
		}
		json.Unmarshal(bytes, &x)
		servicetok = x.Token
	})

	t.Run("create service token from non-master - ok", func(t *testing.T) {
		r := httptest.NewRequest("POST",
			"/v1/create-key?name=stuffer-sub&canon-scopes=stuff_sub",
			http.NoBody)
		//t.Logf("Service = %s", servicetok)
		r.Header.Set("Authorization", "Bearer "+servicetok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusOK, "token", "name")
	})

	t.Run("add user scopes via service token - fail scope", func(t *testing.T) {
		r := httptest.NewRequest("POST",
			"/v1/add-user-scopes?user=foo&scopes=fail_scope",
			http.NoBody)
		//t.Logf("Service = %s", servicetok)
		r.Header.Set("Authorization", "Bearer "+servicetok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusForbidden)
	})

	t.Run("add user scopes via service token - fail user", func(t *testing.T) {
		r := httptest.NewRequest("POST",
			"/v1/add-user-scopes?user=no-such-user&scopes=stuff_hello",
			http.NoBody)
		//t.Logf("Service = %s", servicetok)
		r.Header.Set("Authorization", "Bearer "+servicetok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusBadRequest)
	})

	t.Run("add user scopes via service token - ok", func(t *testing.T) {
		r := httptest.NewRequest("POST",
			"/v1/add-user-scopes?user=foo&scopes=stuff_hello,stuff_bye",
			http.NoBody)
		//t.Logf("Service = %s", servicetok)
		r.Header.Set("Authorization", "Bearer "+servicetok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusOK)
	})

	t.Run("get user scopes - fail user", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/get-user-scopes?user=no-such-user", nil)
		//t.Logf("Service = %s", servicetok)
		r.Header.Set("Authorization", "Bearer "+servicetok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		ensureResp(t, resp, http.StatusBadRequest)
	})

	t.Run("get user scopes, confirm added scopes", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/get-user-scopes?user=foo", nil)
		//t.Logf("Service = %s", servicetok)
		r.Header.Set("Authorization", "Bearer "+servicetok)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		resp := w.Result()
		bytes := ensureResp(t, resp, http.StatusOK, "name", "scopes")
		var x struct {
			Name   string `json:"name"`
			Scopes Scopes `json:"scopes"`
		}
		json.Unmarshal(bytes, &x)
		if x.Name != "foo" {
			t.Error("wrong user name")
		}
		if x.Scopes.Has("fail_scope") ||
			!x.Scopes.Has("stuff_hello") || !x.Scopes.Has("stuff_bye") {
			t.Errorf("Unexpected scopes: %v", x.Scopes)
		}
	})
}

// ensureFields ensures these fields are not missing nor empty strings in the response body JSON.
// If status >= 400, automatically expects to see an error field if the response is JSON.
// If status < 400, automatically expects no error field if the response is JSON.
func ensureResp(t *testing.T, resp *http.Response, status int, ensureFields ...string) []byte {
	bytes, _ := ioutil.ReadAll(resp.Body)
	t.Logf("%s", bytes)
	if resp.StatusCode != status {
		t.Errorf("got wrong HTTP status code; expected %d, got %s",
			status, resp.Status)
		return nil
	}
	if strings.Index(resp.Header.Get("Content-Type"), "json") != -1 {
		var x map[string]interface{}
		err := json.Unmarshal(bytes, &x)
		if err != nil {
			t.Errorf("expected JSON response body, failed to parse: %s", err)
			return nil
		}
		jerror, _ := x["error"].(string)
		gotError := jerror != ""
		wantError := status >= 400
		if gotError != wantError {
			s := "ok"
			if wantError {
				s = "error"
			}
			t.Errorf("expected %s response body, got %s", s, bytes)
			return nil
		}
		for _, f := range ensureFields {
			v := x[f]
			if v == nil {
				t.Errorf(`Did not find JSON field "%s"`, f)
			}
			if s, ok := v.(string); ok && s == "" {
				t.Errorf(`JSON field "%s" is set to an empty string`, f)
			}
		}
	} else {
		t.Log("Response not JSON")
		if len(ensureFields) > 0 {
			t.Errorf("Did not find JSON fields %v (response not JSON)", ensureFields)
		}
	}
	return bytes
}
