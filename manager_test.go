package authentication

import (
	"bytes"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/ticketmaster/authentication/authorization"
	"github.com/ticketmaster/authentication/client"
)

var validManagerConfig = []byte(`
authenticationClient:
  - provider: ldap
    endpoint: dc1.mydomain.com
    baseDN: DC=mydomain,DC=com
    port: 389
    useTLS: true
    shortDomain: mydomain
    tlsServerName: my.mydomain.com
  - provider: memory
    origin: testOrigin
    users:
        - username: test
          password: testpass
          name: My Name
          email: test@test.com
          roles:
              - testRole
              - testRole2
        - username: test2
          password: testpass2
          name: My Name2
          email: test2@test.com
  - provider: unknownProvider

authorization:
  default: deny
  rules:
    - ruleType: action
      action: 
        - "."
      authorize: allow
      role: testRole
      origin: testOrigin
    - ruleType: action
      action: 
        - App\.Index
      authorize: allow
      role: "Anonymous"
      origin: ".*"

privateKey: test-certificates/jwt.rsa
publicKey: test-certificates/jwt.rsa.pub
jwtExpiration: 1h
`)

var manager *Manager

func TestNewManager(t *testing.T) {
	viper.SetConfigType("yaml")
	viper.ReadConfig(bytes.NewBuffer(validManagerConfig))

	mgr, err := NewManager()
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, 2, len(mgr.AuthenticationClients))
	assert.Equal(t, "deny", mgr.Authorization.Default)
	assert.Equal(t, 2, len(mgr.Authorization.Rules))
	privateKey, publicKey, err := getKeys()
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, privateKey, mgr.PrivateKey)
	assert.Equal(t, publicKey, mgr.PublicKey)
	assert.Equal(t, time.Duration(1*time.Hour), mgr.JwtExpiration)
	assert.Equal(t, false, mgr.EnableAnonymousAccess)

	manager = mgr
}

func TestCreateAnonymousUser(t *testing.T) {
	_, err := manager.CreateAnonymousUser()
	assert.Error(t, err, "anonymous access it not permitted")

	manager.EnableAnonymousAccess = true
	u, err := manager.CreateAnonymousUser()
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, "", u.Email)
	assert.Equal(t, "Anonymous User", u.Name)
	assert.Equal(t, "Anonymous", u.Origin)
	assert.Contains(t, u.Roles, "Anonymous")
	assert.Equal(t, "Anonymous", u.Username)

	manager.EnableAnonymousAccess = false
}

func TestValidateCredentials(t *testing.T) {
	u, err := manager.ValidateCredentials("test", "testpass")
	if err != nil {
		t.Error(err)
		return
	}

	assert.Equal(t, "test", u.Username)

	_, err = manager.ValidateCredentials("test", "invalidpass")
	assert.Error(t, err, "invalid username or password")

	clients := manager.AuthenticationClients
	manager.AuthenticationClients = []client.Client{}
	_, err = manager.ValidateCredentials("test", "invalidpass")
	assert.Error(t, err, "no authentication providers enabled")
	manager.AuthenticationClients = clients
}

func TestIsAuthorized(t *testing.T) {
	u, err := manager.ValidateCredentials("test", "testpass")
	if err != nil {
		t.Error(err)
		return
	}

	assert.Equal(t, "test", u.Username)

	authorized := manager.IsAuthorized(u, map[string]string{"route": "/test", "action": "Home.Index"})
	assert.Equal(t, true, authorized)

	authorized = manager.IsAuthorized(u, map[string]string{"route": "/test"})
	assert.Equal(t, false, authorized)

	priorAction := manager.Authorization.Rules[0].(*authorization.ActionRule).Action[0]
	manager.Authorization.Rules[0].(*authorization.ActionRule).Action[0] = "MyTestAction"
	authorized = manager.IsAuthorized(u, map[string]string{"route": "/test", "action": "Home.Index"})
	assert.Equal(t, false, authorized)
	manager.Authorization.Rules[0].(*authorization.ActionRule).Action[0] = priorAction
}
