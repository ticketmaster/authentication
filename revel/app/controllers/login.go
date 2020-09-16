package controllers

import (
	"errors"

	"github.com/revel/revel"
	module "github.com/tickemaster/authentication/revel"
)

// Authentication is the authentication controller
type Authentication struct {
	*revel.Controller
}

// Login provides functionality to return a JWT for a user
func (c Authentication) Login() revel.Result {
	request := struct {
		Username string
		Password string
	}{"", ""}
	err := c.Params.BindJSON(&request)
	if err != nil {
		revel.ERROR.Println(err)
		return c.RenderError(err)
	}

	config, err := module.CreateAuthenticationConfig()
	if err != nil {
		revel.ERROR.Println(err)
		return c.RenderError(err)
	}

	if !config.EnableJwtAuthentication {
		err := errors.New("JWT authentication is disabled")
		revel.ERROR.Println(err)
		return c.RenderError(err)
	}

	user, err := config.AuthenticationManager.ValidateCredentials(request.Username, request.Password)
	if err != nil {
		revel.ERROR.Println(err)
		return c.RenderError(err)
	}

	token, err := config.AuthenticationManager.GetJwt(user)
	if err != nil {
		revel.ERROR.Println(err)
		return c.RenderError(err)
	}

	c.Controller.Session["jwt"] = token
	return c.RenderJSON(struct{ Token string }{token})
}

// Logout clears the JWT with this session
func (c Authentication) Logout() revel.Result {
	config, err := module.CreateAuthenticationConfig()
	if err != nil {
		revel.ERROR.Println(err)
		return c.RenderError(err)
	}

	if !config.EnableJwtAuthentication {
		err := errors.New("JWT authentication is disabled")
		revel.ERROR.Println(err)
		return c.RenderError(err)
	}

	c.Controller.Session["jwt"] = ""
	return c.RenderJSON(struct{ Message string }{"Log out succeeded"})
}
