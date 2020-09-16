package revel

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/tickemaster/authentication/common"

	"github.com/revel/revel"
)

// ValidateCredentials will prompt for credentials and validate them
func ValidateCredentials(c *revel.Controller, filterChain []revel.Filter) {
	if c.Action == "Authentication.Login" {
		// Skip auth for login page
		filterChain[0](c, filterChain[1:]) // Execute the next filter stage.
		return
	}

	config, err := CreateAuthenticationConfig()
	if err != nil {
		revel.ERROR.Println(err)
		c.Result = c.RenderError(err)
		return
	}

	var user *common.User
	// Validate JWT stores in session
	tokenString := c.Session["jwt"]
	if config.EnableJwtAuthentication && len(tokenString) > 0 {
		user, err = validateJwt(c, tokenString)
		if err != nil {
			revel.ERROR.Println(err)
			c.Result = c.RenderError(err)
			return
		}
	} else if auth := c.Request.Header.Get("Authorization"); auth != "" {
		authHeader := strings.Split(auth, " ")
		switch authHeader[0] {
		case "Bearer":
			if !config.EnableJwtAuthentication {
				err := errors.New("JWT provided, but is not enabled for authentication")
				revel.ERROR.Println(err)
				c.Result = c.RenderError(err)
				return
			}

			user, err = validateJwt(c, authHeader[1])
			if err != nil {
				revel.ERROR.Println(err)
				c.Result = c.RenderError(err)
				return
			}
		case "Basic":
			username, password, err := getCredentials(authHeader[1])
			if err != nil {
				revel.ERROR.Println(err)
				c.Result = c.RenderError(err)
				return
			}

			user, err = config.AuthenticationManager.ValidateCredentials(username, password)
			if err != nil {
				if strings.Index(strings.ToLower(err.Error()), "invalid credentials") == -1 {
					revel.ERROR.Println(err)
					c.Result = c.RenderError(err)
					return
				}

				unauthorized(c, config)
				return
			}
		default:
			err := errors.New("unrecognized authentication header")
			revel.ERROR.Println(err)
			c.Result = c.RenderError(err)
			return
		}
	} else {
		if config.AuthenticationManager.EnableAnonymousAccess {
			user, err = config.AuthenticationManager.CreateAnonymousUser()
			if err != nil {
				revel.ERROR.Println(err)
				c.Result = c.RenderError(err)
				return
			}
		} else {
			if config.AuthenticationManager.Authorization.Default != "allow" {
				unauthorized(c, config)
				return
			}
		}

	}

	if user != nil {
		authorized := config.AuthenticationManager.IsAuthorized(user, map[string]string{"action": c.Action, "route": c.Request.RequestURI, "method": c.Request.Method})
		if !authorized {
			c.Response.Status = http.StatusUnauthorized
			c.Result = c.RenderError(errors.New("401: Not authorized"))
			return
		}
		setUserData(c, user)
	} else {
		err = errors.New("unrecognized user")
		revel.ERROR.Println(err)
		c.Result = c.RenderError(err)
		return
	}
	filterChain[0](c, filterChain[1:]) // Execute the next filter stage.
}

func validateJwt(c *revel.Controller, tokenString string) (*common.User, error) {
	config, err := CreateAuthenticationConfig()
	if err != nil {
		return nil, err
	}

	if config.EnableJwtAuthentication && len(tokenString) > 0 {
		user, err := config.AuthenticationManager.CreateUserFromTokenString(tokenString)
		if err != nil {
			return nil, err
		}

		// Refresh token as needed
		newTokenString, err := config.AuthenticationManager.RefreshJwt(user)
		if err != nil {
			return nil, err
		}
		if tokenString != newTokenString {
			c.Session["jwt"] = newTokenString
		}

		return user, nil
	}

	return nil, errors.New("no token string provided")
}

func setUserData(c *revel.Controller, user *common.User) {
	c.Flash.Data["username"] = user.Username
	c.Flash.Data["name"] = user.Name
	c.Flash.Data["email"] = user.Email
}

func unauthorized(c *revel.Controller, config *AuthenticationConfig) {
	c.Response.Status = http.StatusUnauthorized
	c.Result = c.RenderError(errors.New("401: Not authorized"))
	if config.EnableBasicAuthentication {
		c.Response.Out.Header().Add("WWW-Authenticate", `Basic realm="revel"`)
	}

	if config.EnableJwtAuthentication {
		c.Response.Out.Header().Add("WWW-Authenticate", `Bearer`)
	}
}

func getCredentials(data string) (username, password string, err error) {
	decodedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", "", err
	}
	strData := strings.Split(string(decodedData), ":")
	username = strData[0]
	password = strData[1]
	return
}
