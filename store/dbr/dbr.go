// Copyright (C) 2020 Christopher E. Miller
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package dbr_store

import (
	"context"
	"errors"
	"reflect"
	"strings"

	"github.com/gocraft/dbr/v2"
	"github.com/millerlogic/auth-service/store"
)

type dbrRun struct {
	dbr dbr.SessionRunner
}

func (run *dbrRun) update(ctx context.Context, table string, id int64, record interface{}, fieldNames ...string) error {
	b := run.dbr.Update(table).Where("id=?", id)
	b, err := dbrUpdate(b, record, fieldNames)
	if err != nil {
		return fixDbrErr(err)
	}
	_, err = b.ExecContext(ctx)
	if err != nil {
		return fixDbrErr(err)
	}
	return nil
}

func (run *dbrRun) GetUser(ctx context.Context, id int64) (*store.UserModel, error) {
	user := &store.UserModel{}
	err := run.dbr.Select("*").From("users").Where("id=?", id).LoadOneContext(ctx, user)
	if err != nil {
		return nil, fixDbrErr(err)
	}
	return user, nil
}

func (run *dbrRun) GetUserByName(ctx context.Context, name string) (*store.UserModel, error) {
	user := &store.UserModel{}
	err := run.dbr.Select("*").From("users").
		Where("LOWER(name) = LOWER(?)", name).LoadOneContext(ctx, user)
	if err != nil {
		return nil, fixDbrErr(err)
	}
	return user, nil
}

var patternReplacer = strings.NewReplacer(
	`\`, `\\`,
	"%", "\\%",
	"_", "\\_",
	"*", "%",
	"?", "_",
)

func (run *dbrRun) FindUsers(ctx context.Context, pattern string, limit int) ([]*store.UserModel, error) {
	if limit < 0 {
		return nil, errors.New("invalid limit")
	}
	newpattern := patternReplacer.Replace(pattern)
	var users []*store.UserModel
	_, err := run.dbr.Select("*").From("users").
		Where("name like ?", newpattern).
		OrderAsc("len(name)").Limit(uint64(limit)).
		LoadContext(ctx, &users)
	if err != nil {
		return nil, fixDbrErr(err)
	}
	return users, nil
}

func (run *dbrRun) UpdateUser(ctx context.Context, user *store.UserModel, fieldNames ...string) error {
	return run.update(ctx, "users", user.ID, user, fieldNames...)
}

func (run *dbrRun) InsertUser(ctx context.Context, user *store.UserModel) error {
	b := run.dbr.InsertInto("users")
	b = dbrInsert(b, user)
	_, err := b.ExecContext(ctx)
	if err != nil {
		return fixDbrErr(err)
	}
	return nil
}

func (run *dbrRun) GetSetting(ctx context.Context, name string) (*store.SettingModel, error) {
	setting := &store.SettingModel{}
	err := run.dbr.Select("*").From("settings").
		Where("name=?", name).
		LoadOneContext(ctx, setting)
	if err != nil {
		return nil, fixDbrErr(err)
	}
	return setting, nil
}

func (run *dbrRun) SetSetting(ctx context.Context, setting *store.SettingModel) error {
	b := run.dbr.InsertInto("settings")
	b = dbrInsert(b, setting)
	//b.OnDuplicateKeyUpdate()/OnConflict
	_, err := b.ExecContext(ctx)
	if err != nil {
		return fixDbrErr(err)
	}
	return nil
}

func (run *dbrRun) GetUserScope(ctx context.Context, userID int64, scopeName string) (*store.UserScopeModel, error) {
	scope := &store.UserScopeModel{}
	err := run.dbr.Select("*").From("user_scopes").
		Where("user_id=? AND scope_name=?", userID, scopeName).
		LoadOneContext(ctx, scope)
	if err != nil {
		return nil, fixDbrErr(err)
	}
	return scope, nil
}

func (run *dbrRun) GetUserScopes(ctx context.Context, userID int64) ([]*store.UserScopeModel, error) {
	var scopes []*store.UserScopeModel
	_, err := run.dbr.Select("*").From("user_scopes").
		Where("user_id=?", userID).
		LoadContext(ctx, &scopes)
	if err != nil {
		return nil, fixDbrErr(err)
	}
	return scopes, nil
}

func (run *dbrRun) InsertUserScope(ctx context.Context, userID int64, scope *store.UserScopeModel) error {
	b := run.dbr.InsertInto("user_scopes")
	b = dbrInsert(b, scope)
	_, err := b.ExecContext(ctx)
	if err != nil {
		return fixDbrErr(err)
	}
	return nil
}

func (run *dbrRun) DeleteUserScope(ctx context.Context, userID int64, scopeName string) error {
	b := run.dbr.DeleteFrom("user_scopes").
		Where("user_id=? AND name=?", userID, scopeName)
	_, err := b.ExecContext(ctx)
	if err != nil {
		return fixDbrErr(err)
	}
	return nil
}

type dbrTx struct {
	dbr *dbr.Tx
	dbrRun
}

func (tx *dbrTx) Rollback() error {
	return tx.dbr.Rollback()
}

func (tx *dbrTx) RollbackUnlessCommitted() {
	tx.dbr.RollbackUnlessCommitted()
}

func (tx *dbrTx) Commit() error {
	return tx.dbr.Commit()
}

type dbrSession struct {
	dbr *dbr.Session
	dbrRun
}

func (sess *dbrSession) Begin(ctx context.Context) (store.DBTx, error) {
	x, err := sess.dbr.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &dbrTx{x, dbrRun{x}}, nil
}

type dbrDB struct {
	dbr *dbr.Connection
}

func (db *dbrDB) NewSession() store.DBSession {
	x := db.dbr.NewSession(nil)
	return &dbrSession{x, dbrRun{x}}
}

func (db *dbrDB) Setup() error {
	// db.dbr.Dialect == "sqlite3"
	_, err := db.dbr.Exec(`
	create table if not exists users (
		id INTEGER PRIMARY KEY, -- user_id
		name TEXT NOT NULL,
		email TEXT NOT NULL DEFAULT '',
		auth TEXT NOT NULL DEFAULT '',
		last_ip TEXT NOT NULL DEFAULT '',
		token_code INTEGER NOT NULL DEFAULT 0,
		last_login timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
		created timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
		flags TEXT NOT NULL DEFAULT ''
	);
	create table if not exists settings (
		name TEXT INTERGER PRIMARY KEY ON CONFLICT REPLACE, -- sqlite3
		value name TEXT NOT NULL
	);
	create table if not exists user_scopes (
		user_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		created timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
		flags TEXT NOT NULL DEFAULT '',
		PRIMARY KEY(user_id, name),
		FOREIGN KEY(user_id) REFERENCES users(id)
	);
	`)
	return err
}

func (db *dbrDB) Close() error {
	return db.dbr.Close()
}

func NewDbrDB(dbrconn *dbr.Connection) store.DB {
	return &dbrDB{dbrconn}
}

func fixDbrErr(err error) error {
	if err == dbr.ErrNotFound {
		return store.ErrNotFound
	}
	return err
}

func iterfields(x interface{}, callback func(fvalue reflect.Value, ft reflect.StructField) error) error {
	v := reflect.Indirect(reflect.ValueOf(x))
	t := v.Type()
	n := v.NumField()
	for i := 0; i < n; i++ {
		fv := v.Field(i)
		ft := t.Field(i)
		err := callback(fv, ft)
		if err != nil {
			return err
		}
	}
	return nil
}

func getDbrColumnName(ft reflect.StructField) string {
	x := strings.Split(ft.Tag.Get("db"), ",")
	if len(x) > 0 && x[0] != "" {
		return x[0]
	}
	return ft.Name
}

func strInStrs(str string, strs []string) int {
	for i, x := range strs {
		if str == x {
			return i
		}
	}
	return -1
}

func dbrUpdate(b *dbr.UpdateBuilder, record interface{}, fieldNames []string) (*dbr.UpdateBuilder, error) {
	var mask uint64
	err := iterfields(record, func(fvalue reflect.Value, ft reflect.StructField) error {
		isID := ft.Name == "Id" || ft.Name == "ID"
		include := len(fieldNames) == 0 && !isID
		if !include {
			ifn := strInStrs(ft.Name, fieldNames)
			if ifn != -1 {
				if isID {
					return errors.New("Cannot update " + ft.Name + " field")
				}
				bit := uint64(1) << uint(ifn)
				if mask&bit != 0 {
					return errors.New("Duplicate field: " + ft.Name)
				}
				mask |= bit
				include = true
			}
		}
		if include {
			colname := getDbrColumnName(ft)
			b = b.Set(colname, fvalue.Interface())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for ifn, fn := range fieldNames {
		if mask&uint64(1)<<uint(ifn) == 0 {
			return nil, errors.New("No such field: " + fn)
		}
	}
	return b, nil
}

func dbrInsert(b *dbr.InsertBuilder, record interface{}) *dbr.InsertBuilder {
	iterfields(record, func(fvalue reflect.Value, ft reflect.StructField) error {
		colname := getDbrColumnName(ft)
		if colname == "Id" || colname == "ID" {
			b.RecordID = fvalue.Addr().Interface().(*int64)
		} else {
			b = b.Pair(colname, fvalue.Interface())
		}
		return nil
	})
	return b
}
