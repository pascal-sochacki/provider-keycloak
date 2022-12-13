package client

import (
	"context"

	"github.com/Nerzal/gocloak/v12"
)

type KeycloakConfig struct {
	Endpoint string
	Username string
	Password string
	Realm    string
}

type KeycloakClient struct {
	client *gocloak.GoCloak
	config *KeycloakConfig
	ctx    context.Context
}

func NewKeycloakClient(config KeycloakConfig) (*KeycloakClient, error) {
	client := gocloak.NewClient(config.Endpoint)
	ctx := context.Background()

	// Just check if we can get one token
	_, err := client.LoginAdmin(ctx, config.Username, config.Password, config.Realm)

	if err != nil {
		return nil, err
	} else {
		return &KeycloakClient{
			client: client,
			config: &config,
			ctx:    ctx,
		}, nil
	}
}

func (c KeycloakClient) GetRealm(realm string) error {
	var token, err = c.loginAdmin()
	if err != nil {
		return err

	}
	_, err = c.client.GetRealm(c.ctx, token.AccessToken, realm)
	if err != nil {
		return err

	}
	return nil
}

func (c KeycloakClient) CreateRealm(name string) (*string, error) {
	var token, err = c.loginAdmin()
	if err != nil {
		return nil, err
	}

	var id string
	id, err = c.client.CreateRealm(c.ctx, token.AccessToken, gocloak.RealmRepresentation{
		Realm: &name,
	})

	return &id, err
}

func (c KeycloakClient) DeleteRealm(name string) error {
	var token, err = c.loginAdmin()
	if err != nil {
		return err
	}

	return c.client.DeleteRealm(c.ctx, token.AccessToken, name)
}

func (c KeycloakClient) loginAdmin() (*gocloak.JWT, error) {
	return c.client.LoginAdmin(c.ctx, c.config.Username, c.config.Password, c.config.Realm)
}
