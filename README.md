# auth-service
Authentication and rights service and API in Go (golang)

Auth-service allows this one centralized service to manage authentication and rights management
across various services without having to share a secret.

A private key is used to cryptographically secure access tokens for other serivices to confirm against the public key.

The web service has methods:

* /pubkey - to allow anyone to get the public key for verifying tokens.
* /login - allows a user to login directly.
* /login-as - allows a service with scope user_login_as to create a user.
* /signup - allows a user to sign up directly (unless -allowUserSignup=false), or a service to sign up a user.
* /create-key - allows a service to create other service tokens.
* /validate - to validate a token.
* /update-user - allows a user to update their user account, they first have to login with scope user_edit.
* /get-user - allows a user to get information on their own user account.
* /get-user-scopes - allows a service to get scope information for a user, but only scopes the service is allowed to see.
* /add-user-scopes - allows a service to add scopes for a user, but only scopes the service is allowed to manage.
* /remove-user-scopes - *not implemented yet*

Service usage below.

```
Usage of ./auth-service:
  -addr string
    	Address (default ":8080")
  -allowUserSignup
    	Allow users to sign up (create user account) directly (default true)
  -createMaster
    	Create a master key and display it on stdout, expires in 5 minutes
  -dbPath string
    	Set SQLite database path (default "./auth-service.db")
  -exit
    	Exit without starting the service
  -forwardIPAll
    	Enables forwarding ALL requests via the headers X-Forwarded-For or X-Real-IP
  -key string
    	Path to the RSA private key file (default "./auth-service.pem")
  -signupIPRatePeriod duration
    	Allows 1 user signups per IP per this duration (default 24h0m0s)
  -signupRatePeriod duration
    	Allows 3 user signups total per this duration (default 1h0m0s)
  -throttle int
    	Limit concurrent requests, 0 to disable (default 10)
  -timeout duration
    	Request timeout (default 1s)
  -usernamePattern string
    	Override the default valid username regexp pattern
```

Note: this project should probably be renamed.
