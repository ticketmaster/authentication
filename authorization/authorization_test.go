package authorization

import (
	"testing"

	"github.com/tickemaster/authentication/common"
	"github.com/stretchr/testify/assert"
)

var validAuthorization = []byte(`
authorization:
  default: deny
  rules:
    - ruleType: action
      action: 
        - "."
      authorize: allow
      role: testRole
      origin: testOrigin
    - ruleType: route
      route: 
        - /test/route
      authorize: allow
      role: testRole3
      origin: ".*"
    - ruleType: action
      action: 
        - App\.Index
      authorize: allow
      role: "Anonymous"
      origin: ".*"
`)

var invalidAuthorization = []byte(`
authorization:
  default: deny
  rules:
    - ruleType: action
      action: 
        - "."
      authorize: allow
      role: testRole
    - ruleType: route
      route: 
        - /test/route
      method: post
      authorize: allow
      role: testRole2
    - ruleType: action
      action: 
        - App\.Index
      authorize: allow
      role: "Anonymous"
      origin: ".*"
`)

var invalidAuthorization2 = []byte(`
authorization:
  default: deny
  rules:
    - ruleType: action
      action: 
        - "."
      authorize: allow
      role: testRole
      origin: testOrigin
    - ruleType: route
      route: 
        - /test/route
      authorize: allow
      role: testRole2
      origin: ".*"
    - ruleType: action
      action: 
        - (App\.Index
      authorize: allow
      role: "Anonymous"
      origin: ".*"
`)

var defaultAuthorization = []byte(`
authorization:
  rules:
    - ruleType: action
      action: 
        - "."
      authorize: allow
      role: testRole
      origin: testOrigin
    - ruleType: route
      route: 
        - /test/route
      authorize: allow
      role: testRole3
      origin: ".*"
    - ruleType: action
      action: 
        - App\.Index
      authorize: allow
      role: "Anonymous"
      origin: ".*"
`)

func TestNewAuthorization(t *testing.T) {
	var authTests []*Authorization
	authorization, err := NewAuthorization(getConfigElement(validAuthorization))
	if err != nil {
		t.Error(err)
	}
	authTests = append(authTests, authorization)

	authorization, err = NewAuthorization(getConfigElement(defaultAuthorization))
	if err != nil {
		t.Error(err)
	}
	authTests = append(authTests, authorization)

	for _, a := range authTests {
		assert.Equal(t, "deny", a.Default)

		actionRule := a.Rules[0].(*ActionRule)
		assert.Equal(t, ".", actionRule.Action[0])
		assert.Equal(t, "allow", actionRule.Authorize)
		assert.Equal(t, "testOrigin", actionRule.Origin)
		assert.Equal(t, "testRole", actionRule.Role)

		routeRule := a.Rules[1].(*RouteRule)
		assert.Equal(t, "/test/route", routeRule.Route[0])
		assert.Equal(t, "GET", routeRule.Method)
		assert.Equal(t, "allow", routeRule.Authorize)
		assert.Equal(t, ".*", routeRule.Origin)
		assert.Equal(t, "testRole3", routeRule.Role)

		actionRule2 := a.Rules[2].(*ActionRule)
		assert.Equal(t, "App\\.Index", actionRule2.Action[0])
		assert.Equal(t, "allow", actionRule2.Authorize)
		assert.Equal(t, ".*", actionRule2.Origin)
		assert.Equal(t, "Anonymous", actionRule2.Role)
	}

	_, err = NewAuthorization(getConfigElement(invalidAuthorization))
	assert.Error(t, err, "origin parameter must be specified for authorization rule at index 0")

	_, err = NewAuthorization(getConfigElement(invalidAuthorization2))
	assert.Error(t, err, "error parsing regexp: missing closing ): `(App\\.Index`")
}

func TestIsAuthorized(t *testing.T) {
	authorization, err := NewAuthorization(getConfigElement(validAuthorization))
	if err != nil {
		t.Error(err)
	}

	user := &common.User{Origin: "testOrigin", Username: "test", Name: "test Name", Email: "test@test.com", Roles: []string{"testRole", "testRole2"}}
	user2 := &common.User{Origin: "testOrigin", Username: "test", Name: "test Name", Email: "test@test.com", Roles: []string{"testRole3", "testRole4"}}
	anon := &common.User{Origin: "Anonymous", Username: "Anonymous", Name: "Anonymous User", Email: ""}
	anon.Roles = append(user.Roles, "Anonymous")

	assert.Equal(t, true, authorization.IsAuthorized(user, map[string]string{"route": "/abc", "action": "UnspecifiedAction", "method": "GET"}))
	assert.Equal(t, false, authorization.IsAuthorized(anon, map[string]string{"route": "/abc", "action": "UnspecifiedAction", "method": "GET"}))
	assert.Equal(t, true, authorization.IsAuthorized(user, map[string]string{"route": "/abc", "action": "App.Index", "method": "GET"}))
	assert.Equal(t, true, authorization.IsAuthorized(anon, map[string]string{"route": "/abc", "action": "App.Index", "method": "GET"}))
	assert.Equal(t, false, authorization.IsAuthorized(user2, map[string]string{"route": "/abc", "action": "App.Index", "method": "GET"}))
	assert.Equal(t, true, authorization.IsAuthorized(user2, map[string]string{"route": "/test/route", "action": "App.Index", "method": "GET"}))
	assert.Equal(t, false, authorization.IsAuthorized(user2, map[string]string{"route": "/test/route", "action": "App.Index", "method": "POST"}))
	assert.Equal(t, false, authorization.IsAuthorized(user2, map[string]string{}))
	assert.Equal(t, false, authorization.IsAuthorized(user2, nil))

	authorization.Default = "allow"
	assert.Equal(t, true, authorization.IsAuthorized(user2, nil))
	assert.Equal(t, true, authorization.IsAuthorized(user2, map[string]string{"route": "/abc", "action": "App.Index", "method": "GET"}))

	newRule := ActionRule{Action: []string{"App\\.Index"}}
	newRule.Authorize = "deny"
	newRule.Origin = "test."
	newRule.Role = "testRole3"
	authorization.Rules = append(authorization.Rules, newRule)
	assert.Equal(t, false, authorization.IsAuthorized(user2, map[string]string{"route": "/abc", "action": "App.Index", "method": "GET"}))
}
