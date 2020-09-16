package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var validMemoryConfiguration = []byte(`
authenticationClient:
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
`)

func TestNewMemoryClient(t *testing.T) {
	c, err := NewMemoryClient(GetConfigElement(validMemoryConfiguration))
	if err != nil {
		t.Error(err)
		return
	}
	memoryClient := c.(*MemoryClient)

	assert.Equal(t, "testOrigin", memoryClient.Origin)

	assert.Equal(t, "test", memoryClient.Users[0].Username)
	assert.Equal(t, "testpass", memoryClient.Users[0].Password)
	assert.Equal(t, "My Name", memoryClient.Users[0].Name)
	assert.Equal(t, "test@test.com", memoryClient.Users[0].Email)

	assert.Equal(t, "test2", memoryClient.Users[1].Username)
	assert.Equal(t, "testpass2", memoryClient.Users[1].Password)
	assert.Equal(t, "My Name2", memoryClient.Users[1].Name)
	assert.Equal(t, "test2@test.com", memoryClient.Users[1].Email)
}

func TestMemoryGetOrigin(t *testing.T) {
	c, err := NewMemoryClient(GetConfigElement(validMemoryConfiguration))
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, "testOrigin", c.GetOrigin())
}

func TestMemoryValidateCredentials(t *testing.T) {
	c, err := NewMemoryClient(GetConfigElement(validMemoryConfiguration))
	if err != nil {
		t.Error(err)
	}

	u, err := c.ValidateCredentials("test", "testpass")
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, "test", u.Username)
	assert.Equal(t, "My Name", u.Name)
	assert.Equal(t, "test@test.com", u.Email)
	assert.Equal(t, "testRole", u.Roles[0])
	assert.Equal(t, "testRole2", u.Roles[1])

	u, err = c.ValidateCredentials("test2", "testpass2")
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, "test2", u.Username)
	assert.Equal(t, "My Name2", u.Name)
	assert.Equal(t, "test2@test.com", u.Email)
	assert.Equal(t, 0, len(u.Roles))
}
