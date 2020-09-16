package common

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var user = &User{Origin: "testOrigin", Username: "test", Name: "test Name", Email: "test@test.com", Roles: []string{"testRole", "testRole2"}}
var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey
var expiredToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJleHAiOjE0OTk3Nzk1MDMsImlhdCI6MTQ5OTc3OTQ0MywibmFtZSI6InRlc3QgTmFtZSIsIm9yaWdpbiI6InRlc3RPcmlnaW4iLCJyb2xlcyI6WyJ0ZXN0Um9sZSIsInRlc3RSb2xlMiJdLCJzdWIiOiJ0ZXN0IiwidXNlcm5hbWUiOiJ0ZXN0In0.ALetC514LvnibwogZDD8ztpOnW80uYX7mOQUP3LWqNDnylqJgudz-L_UroqvLdc_GewuxezjxaNoiP16ryiRvBkqFwyYEGtH1GArxN4ZkbDA5c0OG0vITEoA5AYaCdlMUFKQSVhE3ZLVLIgp_1t-Aii3pHYC2FwJzil1HcmPYNrWHS7sevFR8fF6oyBrOaFkau4luo7NSWhzZTZUT5cALm901u1dpBwazMDF3EeTSKF_m2pnYAV-N8zbPH9x6bGHHQlVsWyQpTtK_Ei2zg543lbJmr28ITgnq4s2BBrZ6AW_cDXJD3F7DAIyF9-kQ1FAm5KLcEpY2ArQ8ALyrSJnYw"

func init() {
	priv, pub, err := getKeys()
	if err != nil {
		panic(err)
	}

	privateKey = priv
	publicKey = pub
}

func TestCreateUserFromTokenString(t *testing.T) {
	token, err := user.GetJwt(privateKey, time.Duration(1*time.Hour))
	if err != nil {
		t.Error(err)
	}
	u, err := CreateUserFromTokenString(token, publicKey)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, user.Email, u.Email)
	assert.Equal(t, user.Name, u.Name)
	assert.Equal(t, user.Origin, u.Origin)
	assert.Equal(t, user.Roles, u.Roles)
	assert.Equal(t, user.Username, u.Username)

	u, err = CreateUserFromTokenString(expiredToken, publicKey)
	assert.Error(t, err, "Token is expired")
}
func TestGetJwt(t *testing.T) {
	token, err := user.GetJwt(privateKey, time.Duration(1*time.Hour))
	if err != nil {
		t.Error(err)
	}

	assert.NotEmpty(t, token)
}

func TestRefreshJwt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}
	u := &User{Origin: "testOrigin", Username: "test", Name: "test Name", Email: "test@test.com", Roles: []string{"testRole", "testRole2"}}
	token, err := u.RefreshJwt(privateKey, time.Duration(3*time.Second))
	if err != nil {
		t.Error(err)
	}

	assert.NotEmpty(t, token)
	token2, err := u.RefreshJwt(privateKey, time.Duration(4*time.Second))
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, token, token2)
	time.Sleep(time.Duration(3 * time.Second))
	token3, err := u.RefreshJwt(privateKey, time.Duration(4*time.Second))
	if err != nil {
		t.Error(err)
	}
	assert.NotEqual(t, token, token3)
}
func TestUserHasRole(t *testing.T) {
	assert.Equal(t, true, user.HasRole("testRole"))
	assert.Equal(t, true, user.HasRole("testRole2"))
	assert.Equal(t, false, user.HasRole("notValidRole"))
}
