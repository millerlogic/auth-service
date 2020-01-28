// Copyright (C) 2020 Christopher E. Miller
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"errors"
	"time"
)

type DB interface {
	Setup() error
	NewSession() DBSession
	Close() error
}

var ErrNotFound = errors.New("not found")

// Functions can return ErrNotFound if the thing wasn't found.
type DBRunner interface {
	GetUser(ctx context.Context, id int64) (*UserModel, error)
	GetUserByName(ctx context.Context, name string) (*UserModel, error)
	FindUsers(ctx context.Context, pattern string, limit int) ([]*UserModel, error)
	UpdateUser(ctx context.Context, user *UserModel, fieldNames ...string) error
	InsertUser(ctx context.Context, user *UserModel) error // The ID must be 0.
	GetSetting(ctx context.Context, name string) (*SettingModel, error)
	SetSetting(ctx context.Context, setting *SettingModel) error
	GetUserScope(ctx context.Context, userID int64, scopeName string) (*UserScopeModel, error)
	GetUserScopes(ctx context.Context, userID int64) ([]*UserScopeModel, error)
	// Use Delete+Insert to update a user scope.
	InsertUserScope(ctx context.Context, userID int64, scope *UserScopeModel) error
	DeleteUserScope(ctx context.Context, userID int64, scopeName string) error
}

type DBSession interface {
	DBRunner
	Begin(ctx context.Context) (DBTx, error)
}

// DB transaction
type DBTx interface {
	DBRunner
	Rollback() error
	RollbackUnlessCommitted()
	Commit() error
}

// UserModel represents a User.
// Flags:
// 	c = confirmed account.
// 	s = suspended account.
// 	d = deleted account.
type UserModel struct {
	ID        int64
	Name      string
	Email     string
	Auth      string
	LastIP    string    `db:"last_ip"`
	TokenCode int       `db:"token_code"`
	LastLogin time.Time `db:"last_login"`
	Created   time.Time
	Flags     string
}

func (user *UserModel) GetID() int64 {
	return user.ID
}

func (user *UserModel) GetName() string {
	return user.Name
}

func (user *UserModel) GetCreated() time.Time {
	return user.Created
}

func (user *UserModel) GetFlags() string {
	return user.Flags
}

type SettingModel struct {
	Name  string
	Value string
}

func (setting *SettingModel) GetName() string {
	return setting.Name
}

func (setting *SettingModel) GetValue() string {
	return setting.Value
}

// Flags:
// 	e = exclude scope by default, must be requested explicitly.
type UserScopeModel struct {
	UserID  int64     `db:"user_id"`
	Name    string    // scope name
	Created time.Time // when the scope was added for this user.
	Flags   string
}

func (scope *UserScopeModel) GetName() string {
	return scope.Name
}

func (scope *UserScopeModel) GetCreated() time.Time {
	return scope.Created
}

func (scope *UserScopeModel) GetFlags() string {
	return scope.Flags
}
