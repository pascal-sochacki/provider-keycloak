package client

import (
	"context"
	"encoding/json"

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
	token  gocloak.JWT
	config *KeycloakConfig
	ctx    context.Context
}

func NewKeycloakClientFromJson(creds []byte) (*KeycloakClient, error) {
	var config KeycloakConfig
	err := json.Unmarshal(creds, &config)
	if err != nil {
		return nil, err
	}

	keycloakClient, err := NewKeycloakClient(config)
	return keycloakClient, err
}

func NewKeycloakClient(config KeycloakConfig) (*KeycloakClient, error) {
	client := gocloak.NewClient(config.Endpoint)
	ctx := context.Background()

	token, err := client.LoginAdmin(ctx, config.Username, config.Password, config.Realm)

	if err != nil {
		return nil, err
	} else {
		return &KeycloakClient{
			client: client,
			token:  *token,
			config: &config,
			ctx:    ctx,
		}, nil
	}
}

func bPointer(i bool) *bool {
	return &i
}

func sPointer(i string) *string {
	return &i
}
