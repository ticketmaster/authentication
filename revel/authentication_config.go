package revel

import (
	"github.com/revel/revel"
	"github.com/spf13/viper"
	"github.com/ticketmaster/authentication"
)

// AuthenticationConfig is a struct that holds authentication package information
type AuthenticationConfig struct {
	EnableJwtAuthentication   bool
	EnableBasicAuthentication bool
	AuthenticationManager     *authentication.Manager
}

var config *AuthenticationConfig

// CreateAuthenticationConfig reads config files and prepares the authentication middleware for use
func CreateAuthenticationConfig() (*AuthenticationConfig, error) {
	if config != nil {
		return config, nil
	}

	config := revel.Config.StringDefault("authentication.config.name", "authentication")
	configPath := revel.Config.StringDefault("authentication.config.path", "./conf")
	viper.SetConfigName(config)
	viper.AddConfigPath(configPath)
	viper.SetEnvPrefix("AUTH")
	err := viper.ReadInConfig()
	if err != nil {
		return nil, err
	}

	manager, err := authentication.NewManager()
	if err != nil {
		return nil, err
	}

	jwt := revel.Config.BoolDefault("authentication.enableJwtAuth", true)
	basic := revel.Config.BoolDefault("authentication.enableBasicAuth", true)
	return &AuthenticationConfig{jwt, basic, manager}, nil
}
