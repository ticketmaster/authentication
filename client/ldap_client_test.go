package client

import (
	"testing"

	"github.com/tickemaster/authentication/common"
	"github.com/stretchr/testify/assert"
)

var validConfiguration = []byte(`
authenticationClient:
  - provider: ldap
    endpoint: dc1.mydomain.com
    baseDN: DC=mydomain,DC=com
    port: 389
    useTLS: true
    shortDomain: mydomain
    tlsServerName: my.mydomain.com
`)

var validConfigurationWithDefaults = []byte(`
authenticationClient:
  - provider: ldap
    endpoint: dc1.mydomain.com
    baseDN: DC=mydomain,DC=com
    shortDomain: mydomain
`)

var invalidConfigurationMissingRequired = []byte(`
authenticationClient:
  - provider: ldap
    baseDN: DC=mydomain,DC=com
    port: 389
    useTLS: true
    shortDomain: mydomain
`)

var validValues = map[string]interface{}{
	"BaseDN":             "DC=mydomain,DC=com",
	"Endpoint":           "dc1.mydomain.com",
	"InsecureSkipVerify": false,
	"Port":               389,
	"ShortDomain":        "mydomain",
	"TLSServerName":      "dc1.mydomain.com",
	"UseTLS":             true}

func validateLdapClient(t *testing.T, config []byte, valid map[string]interface{}) {
	c, err := NewLdapClient(GetConfigElement(config))
	if err != nil {
		t.Error(err)
		return
	}
	ldapClient := c.(*LdapClient)

	assert.Equal(t, valid["BaseDN"].(string), ldapClient.BaseDN)
	assert.Equal(t, valid["Endpoint"].(string), ldapClient.Endpoint)
	assert.Equal(t, valid["InsecureSkipVerify"].(bool), ldapClient.InsecureSkipVerify)
	assert.Equal(t, valid["Port"].(int), ldapClient.Port)
	assert.Equal(t, valid["ShortDomain"].(string), ldapClient.ShortDomain)
	assert.Equal(t, valid["TLSServerName"].(string), ldapClient.TLSServerName)
	assert.Equal(t, valid["UseTLS"].(bool), ldapClient.UseTLS)
}
func TestNewLdapClient(t *testing.T) {
	vm := common.CopyMap(validValues)
	vm["TLSServerName"] = "my.mydomain.com"
	validateLdapClient(t, validConfiguration, vm)
	validateLdapClient(t, validConfigurationWithDefaults, validValues)
	_, err := NewLdapClient(GetConfigElement(invalidConfigurationMissingRequired))
	assert.Error(t, err, "endpoint must be specified in configuration")
}

func TestGetOrigin(t *testing.T) {
	c, err := NewLdapClient(GetConfigElement(validConfiguration))
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, validValues["ShortDomain"].(string), c.GetOrigin())
}

func TestParseUsername(t *testing.T) {
	c, err := NewLdapClient(GetConfigElement(validConfiguration))
	if err != nil {
		t.Error(err)
		return
	}
	ldapClient := c.(*LdapClient)

	samAccountName, domain, err := ldapClient.parseUsername("testUser")
	if err != nil {
		t.Error(err)
	} else {
		assert.Equal(t, "testUser", samAccountName)
		assert.Equal(t, "mydomain", domain)
	}

	samAccountName, domain, err = ldapClient.parseUsername("mydomain\\testUser")
	if err != nil {
		t.Error(err)
	} else {
		assert.Equal(t, "testUser", samAccountName)
		assert.Equal(t, "mydomain", domain)
	}

	// Last domain segment is really ignored and default used
	samAccountName, domain, err = ldapClient.parseUsername("testUser@mydomain.com")
	if err != nil {
		t.Error(err)
	} else {
		assert.Equal(t, "testUser", samAccountName)
		assert.Equal(t, "mydomain", domain)
	}

	samAccountName, domain, err = ldapClient.parseUsername("anotherdomain\\testUser")
	if err != nil {
		t.Error(err)
	} else {
		assert.Equal(t, "testUser", samAccountName)
		assert.Equal(t, "anotherdomain", domain)
	}

	// Last domain segment is really ignored and default used
	samAccountName, domain, err = ldapClient.parseUsername("testUser@anotherdomain.com")
	if err != nil {
		t.Error(err)
	} else {
		assert.Equal(t, "testUser", samAccountName)
		assert.Equal(t, "mydomain", domain)
	}
}
