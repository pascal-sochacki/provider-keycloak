package client

import (
	"github.com/Nerzal/gocloak/v12"
	"github.com/pascal-sochacki/provider-keycloak/apis/v1alpha1"
)

func (c KeycloakClient) GetGroup(realm string, groupId string) (*v1alpha1.GroupParameters, error) {
	_, err := c.client.GetGroup(c.ctx, c.token.AccessToken, realm, groupId)
	if err != nil {
		return nil, err
	}
	return &v1alpha1.GroupParameters{
		Realm: realm,
	}, nil
}

func (c KeycloakClient) CreateGroup(realm string, name string) (*string, error) {
	id, err := c.client.CreateGroup(c.ctx, c.token.AccessToken, realm, gocloak.Group{
		Name: &name,
	})

	return &id, err
}

func (c KeycloakClient) DeleteGroup(realm string, groupId string) error {
	return c.client.DeleteGroup(c.ctx, c.token.AccessToken, realm, groupId)
}
