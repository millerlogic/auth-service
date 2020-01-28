package main

import "testing"

func TestScopes(t *testing.T) {
	var scopes Scopes = []string{"foo_bar", "baz"}
	t.Logf("%#v", scopes)
	for i, x := range [][2]string{
		// scope, t/f
		{"", "f"},
		{"_", "f"},
		{"__", "f"},
		{"foo_bar", "t"},
		{"baz", "t"},
		{"foo", "f"},
		{"Foo_bar", "f"},
		{"baz_hello", "f"},
		{"baz_hello_world", "f"},
		{"foo_bar_cat", "f"},
		{"hello_world_very_long_fake_scope", "f"},
	} {
		scope := x[0]
		expect := x[1] == "t"
		got := scopes.Has(scope)
		if expect != got {
			t.Errorf("[%d] scope %s expected %v, got %v", i, scope, expect, got)
		}
	}
}

func TestCanonScopes(t *testing.T) {
	var canonScopes CanonScopes = []string{"foo_bar", "baz"}
	t.Logf("%#v", canonScopes)
	for i, x := range [][2]string{
		// scope, t/f
		{"", "f"},
		{"_", "f"},
		{"__", "f"},
		{"foo_bar", "t"},
		{"baz", "t"},
		{"foo", "f"},
		{"Foo_bar", "f"},
		{"baz_hello", "t"},
		{"baz_hello_world", "t"},
		{"foo_bar_cat", "t"},
		{"hello_world_very_long_fake_scope", "f"},
	} {
		scope := x[0]
		expect := x[1] == "t"
		got := canonScopes.Allowed(scope)
		if expect != got {
			t.Errorf("[%d] scope %s expected %v, got %v", i, scope, expect, got)
		}
	}
}
