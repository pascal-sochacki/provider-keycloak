package client

import (
	"github.com/Nerzal/gocloak/v12"
	"github.com/pascal-sochacki/provider-keycloak/apis/v1alpha1"
)

func (c KeycloakClient) GetUser(realm string, userId string) (*v1alpha1.UserParameters, error) {
	user, err := c.client.GetUserByID(c.ctx, c.token.AccessToken, realm, userId)
	if err != nil {
		return nil, err
	}
	return &v1alpha1.UserParameters{
		Realm:    realm,
		Username: *user.Username,
		Email:    user.Email,
	}, nil
}

func (c KeycloakClient) CreateUser(user v1alpha1.UserParameters) (*string, error) {
	userId, err := c.client.CreateUser(c.ctx, c.token.AccessToken, user.Realm, mapUser(user))
	return &userId, err
}

func (c KeycloakClient) UpdateUser(userId string, user v1alpha1.UserParameters) error {
	mappedUser := mapUser(user)
	mappedUser.ID = &userId
	return c.client.UpdateUser(c.ctx, c.token.AccessToken, user.Realm, mappedUser)
}

func (c KeycloakClient) DeleteUser(realm string, userId string) error {
	return c.client.DeleteUser(c.ctx, c.token.AccessToken, realm, userId)
}

func mapUser(user v1alpha1.UserParameters) gocloak.User {
	return gocloak.User{
		Username: &user.Username,
		Email:    user.Email,
	}
}
