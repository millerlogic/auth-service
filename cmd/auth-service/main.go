// Copyright (C) 2020 Christopher E. Miller
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gocraft/dbr/v2"
	_ "github.com/mattn/go-sqlite3"
	dbr_store "github.com/millerlogic/auth-service/store/dbr"
	"golang.org/x/net/netutil"
)

func run() error {
	addr := ":8080"
	flag.StringVar(&addr, "addr", addr, "Address")
	exit := false
	flag.BoolVar(&exit, "exit", exit, "Exit without starting the service")
	dbPath := "./auth-service.db"
	flag.StringVar(&dbPath, "dbPath", dbPath, "Set SQLite database path")
	keyPath := "./auth-service.pem"
	flag.StringVar(&keyPath, "key", keyPath, "Path to the RSA private key file")
	authArgs := AuthArgs{
		Throttle: 10,
		Timeout:  1 * time.Second,
	}
	flag.BoolVar(&authArgs.ForwardIPAll, "forwardIPAll", authArgs.ForwardIPAll,
		"Enables forwarding ALL requests via the headers X-Forwarded-For or X-Real-IP")
	flag.IntVar(&authArgs.Throttle, "throttle", authArgs.Throttle,
		"Limit concurrent requests, 0 to disable")
	flag.DurationVar(&authArgs.Timeout, "timeout", authArgs.Timeout, "Request timeout")
	flag.StringVar(&authArgs.UsernamePattern, "usernamePattern", authArgs.UsernamePattern,
		"Override the default valid username regexp pattern")
	flag.DurationVar(&SignupRateLimit.Period, "signupRatePeriod", SignupRateLimit.Period,
		fmt.Sprintf("Allows %d user signups total per this duration", SignupRateLimit.Limit))
	flag.DurationVar(&SignupIPRateLimit.Period, "signupIPRatePeriod", SignupIPRateLimit.Period,
		fmt.Sprintf("Allows %d user signups per IP per this duration", SignupIPRateLimit.Limit))
	flag.BoolVar(&AllowUserSignup, "allowUserSignup", AllowUserSignup,
		"Allow users to sign up (create user account) directly")
	createMaster := false
	flag.BoolVar(&createMaster, "createMaster", createMaster,
		"Create a master key and display it on stdout, expires in 5 minutes")
	flag.Parse()

	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return err
	}
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return errors.New("unable to load private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	authArgs.PrivateKey = privateKey

	if createMaster {
		masterExpiresIn := 5 * time.Minute
		masterToken, err := newMasterToken(masterExpiresIn, privateKey)
		if err != nil {
			log.Printf("ERROR failed to sign token: %v", err)
		} else {
			fmt.Fprintf(os.Stdout, "Master key: %v (expires in %v)\n",
				masterToken.Raw, masterExpiresIn)
		}
	}

	dbrx, err := dbr.Open("sqlite3", dbPath, nil)
	if err != nil {
		return err
	}
	db := dbr_store.NewDbrDB(dbrx)
	err = db.Setup()
	if err != nil {
		return err
	}
	authArgs.DB = db

	handler := newAuthHandler(authArgs)

	if exit {
		log.Println("exit requested")
		return nil
	}

	baseLn, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	aliveLn := tcpKeepAliveListener{baseLn.(*net.TCPListener)}
	limitLn := netutil.LimitListener(aliveLn, 64)

	httpServer := &http.Server{}
	httpServer.Addr = addr
	httpServer.Handler = handler
	return httpServer.Serve(limitLn)
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %+v\n", err)
		log.Fatalf("ERROR %v", err)
	}
}

// From net/http/server.go
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(2 * time.Minute)
	return tc, nil
}

// for testing and fuzzing:
func newTestAuth() (http.Handler, *rsa.PrivateKey) {
	dbrx, err := dbr.Open("sqlite3", ":memory:", nil)
	if err != nil {
		panic(err)
	}
	db := dbr_store.NewDbrDB(dbrx)
	err = db.Setup()
	if err != nil {
		panic(err)
	}

	// worst possible key:
	// need decent sized key to avoid "message too long for RSA"
	privateKey, err := rsa.GenerateKey(rand.New(rand.NewSource(42)), 1024)
	if err != nil {
		panic(err)
	}

	handler := newAuthHandler(AuthArgs{
		DB:         db,
		PrivateKey: privateKey,
	})

	return handler, privateKey
}
