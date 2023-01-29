package client

import (
	"strconv"
	"strings"

	"github.com/Nerzal/gocloak/v12"
	"github.com/pascal-sochacki/provider-keycloak/apis/v1alpha1"
)

func (c KeycloakClient) GetClient(realm string, id string) (*v1alpha1.ClientParameters, *string, error) {
	client, err := c.client.GetClient(c.ctx, c.token.AccessToken, realm, id)
	if err != nil {
		return nil, nil, err
	}
	_, result := mapClientBack(*client, realm)
	return &result, client.Secret, err
}

func (c KeycloakClient) CreateClient(id string, client v1alpha1.ClientParameters) (*string, error) {
	createdId, err := c.client.CreateClient(c.ctx, c.token.AccessToken, client.Realm, mapClient(id, client))
	return &createdId, err
}

func (c KeycloakClient) UpdateClient(id string, client v1alpha1.ClientParameters) error {
	update := mapClient(id, client)
	return c.client.UpdateClient(c.ctx, c.token.AccessToken, client.Realm, update)
}

func (c KeycloakClient) DeleteClient(realm string, id string) error {
	return c.client.DeleteClient(c.ctx, c.token.AccessToken, realm, id)
}

func mapClient(id string, client v1alpha1.ClientParameters) gocloak.Client {
	attributes := createAttributes(client)

	return gocloak.Client{
		ID:       &id,
		ClientID: &id,

		ClientAuthenticatorType:      client.ClientAuthenticatorType,
		Name:                         client.Name,
		Protocol:                     &client.Protocol,
		Description:                  client.Description,
		RootURL:                      client.RootUrl,
		BaseURL:                      client.HomeUrl,
		RedirectURIs:                 client.ValidRedirectUris,
		Attributes:                   &attributes,
		AdminURL:                     client.AdminUrl,
		WebOrigins:                   client.WebOrigins,
		PublicClient:                 client.PublicClient,
		AuthorizationServicesEnabled: client.AuthorizationServicesEnabled,
		ServiceAccountsEnabled:       client.ServiceAccountsEnabled,
		StandardFlowEnabled:          client.StandardFlowEnabled,
		DirectAccessGrantsEnabled:    client.DirectAccessGrantsEnabled,
		ImplicitFlowEnabled:          client.ImplicitFlowEnabled,
		ConsentRequired:              client.ConsentRequired,
		FrontChannelLogout:           client.FrontChannelLogout,
	}
}

func mapClientBack(client gocloak.Client, realm string) (id string, result v1alpha1.ClientParameters) {
	result = v1alpha1.ClientParameters{
		Realm:                   realm,
		ClientAuthenticatorType: client.ClientAuthenticatorType,

		Name:                         client.Name,
		Protocol:                     *client.Protocol,
		Description:                  client.Description,
		RootUrl:                      client.RootURL,
		HomeUrl:                      client.BaseURL,
		AdminUrl:                     client.AdminURL,
		PublicClient:                 client.PublicClient,
		AuthorizationServicesEnabled: client.AuthorizationServicesEnabled,
		ServiceAccountsEnabled:       client.ServiceAccountsEnabled,
		StandardFlowEnabled:          client.StandardFlowEnabled,
		DirectAccessGrantsEnabled:    client.DirectAccessGrantsEnabled,
		ImplicitFlowEnabled:          client.ImplicitFlowEnabled,
		ConsentRequired:              client.ConsentRequired,
		FrontChannelLogout:           client.FrontChannelLogout,
	}

	if client.RedirectURIs != nil && len(*client.RedirectURIs) > 0 {
		result.ValidRedirectUris = client.RedirectURIs
	}

	if client.WebOrigins != nil && len(*client.WebOrigins) > 0 {
		result.WebOrigins = client.WebOrigins
	}

	if client.AuthorizationServicesEnabled != nil {
		result.AuthorizationServicesEnabled = client.AuthorizationServicesEnabled
	} else {
		result.AuthorizationServicesEnabled = bPointer(false)
	}

	attributes := *client.Attributes
	if attributes != nil {
		setAttributes(attributes, result)
	}

	return *client.ClientID, result
}

const (
	ValidPostLogoutUris                   = "post.logout.redirect.uris"
	Oauth2DeviceAuthorizationGrantEnabled = "oauth2.device.authorization.grant.enabled"
	OidcCibaGrantEnabled                  = "oidc.ciba.grant.enabled"
	LoginTheme                            = "login_theme"
	DisplayClientOnConsentScreen          = "display.on.consent.screen"
	MessageOnConsentScreen                = "consent.screen.text"
	FrontChannelLogoutUrl                 = "frontchannel.logout.url"
	BackChannelLogoutUrl                  = "backchannel.logout.url"
	BackChannelLogoutSessionRequired      = "backchannel.logout.session.required"
	BackchannelLogoutRevokeOfflineTokens  = "backchannel.logout.revoke.offline.tokens"

	SamlIdpInitiatedSsoUrlName    = "saml_idp_initiated_sso_url_name"
	SamlIdpInitiatedSsoRelayState = "saml_idp_initiated_sso_relay_state"
	SamlNameIdFormat              = "saml_name_id_format"
	SamlForceNameIdFormat         = "saml.force.name.id.format"
	SamlForcePostBinding          = "saml.force.post.binding"
	SamlArtifactBinding           = "saml.artifact.binding"
	SamlAuthnstatement            = "saml.authnstatement"
	SamlOnetimeuseCondition       = "saml.onetimeuse.condition"
	SamlServerSignatureKeyinfoExt = "saml.server.signature.keyinfo.ext"
)

func setAttributes(attributes map[string]string, result v1alpha1.ClientParameters) {
	if uriString, found := attributes[ValidPostLogoutUris]; found {
		urisplit := strings.Split(uriString, "##")
		result.ValidPostLogoutUris = &urisplit
	}

	result.Oauth2DeviceAuthorizationGrantEnabled = getAsBool(attributes, Oauth2DeviceAuthorizationGrantEnabled)
	result.OidcCibaGrantEnabled = getAsBool(attributes, OidcCibaGrantEnabled)
	result.LoginTheme = getAsString(attributes, LoginTheme)
	result.DisplayClientOnConsentScreen = getAsBool(attributes, DisplayClientOnConsentScreen)
	result.MessageOnConsentScreen = getAsString(attributes, MessageOnConsentScreen)
	result.FrontChannelLogoutUrl = getAsString(attributes, FrontChannelLogoutUrl)
	result.BackChannelLogoutUrl = getAsString(attributes, BackChannelLogoutUrl)
	result.BackChannelLogoutSessionRequired = getAsBool(attributes, BackChannelLogoutSessionRequired)
	result.BackchannelLogoutRevokeOfflineTokens = getAsBool(attributes, BackchannelLogoutRevokeOfflineTokens)
	result.SamlIdpInitiatedSsoUrlName = getAsString(attributes, SamlIdpInitiatedSsoUrlName)
	result.SamlIdpInitiatedSsoRelayState = getAsString(attributes, SamlIdpInitiatedSsoRelayState)
	result.SamlNameIdFormat = getAsString(attributes, SamlNameIdFormat)
	result.SamlForceNameIdFormat = getAsBool(attributes, SamlForceNameIdFormat)
	result.SamlForcePostBinding = getAsBool(attributes, SamlForcePostBinding)
	result.SamlArtifactBinding = getAsBool(attributes, SamlArtifactBinding)
	result.SamlAuthnstatement = getAsBool(attributes, SamlAuthnstatement)
	result.SamlOnetimeuseCondition = getAsBool(attributes, SamlOnetimeuseCondition)
	result.SamlServerSignatureKeyinfoExt = getAsBool(attributes, SamlServerSignatureKeyinfoExt)
}

//nolint:all
func createAttributes(client v1alpha1.ClientParameters) map[string]string {
	var attributes = map[string]string{}

	if client.ValidPostLogoutUris != nil {
		attributes[ValidPostLogoutUris] = strings.Join(*client.ValidPostLogoutUris, "##")
	}
	if client.Oauth2DeviceAuthorizationGrantEnabled != nil {
		attributes[Oauth2DeviceAuthorizationGrantEnabled] = strconv.FormatBool(*client.Oauth2DeviceAuthorizationGrantEnabled)
	}
	if client.OidcCibaGrantEnabled != nil {
		attributes[OidcCibaGrantEnabled] = strconv.FormatBool(*client.OidcCibaGrantEnabled)
	}
	if client.LoginTheme != nil {
		attributes[LoginTheme] = *client.LoginTheme
	}
	if client.DisplayClientOnConsentScreen != nil {
		attributes[DisplayClientOnConsentScreen] = strconv.FormatBool(*client.DisplayClientOnConsentScreen)
	}
	if client.MessageOnConsentScreen != nil {
		attributes[MessageOnConsentScreen] = *client.MessageOnConsentScreen
	}
	if client.FrontChannelLogoutUrl != nil {
		attributes[FrontChannelLogoutUrl] = *client.FrontChannelLogoutUrl
	}
	if client.BackChannelLogoutUrl != nil {
		attributes[BackChannelLogoutUrl] = *client.BackChannelLogoutUrl
	}
	if client.BackChannelLogoutSessionRequired != nil {
		attributes[BackChannelLogoutSessionRequired] = strconv.FormatBool(*client.BackChannelLogoutSessionRequired)
	}
	if client.BackchannelLogoutRevokeOfflineTokens != nil {
		attributes[BackchannelLogoutRevokeOfflineTokens] = strconv.FormatBool(*client.BackchannelLogoutRevokeOfflineTokens)
	}
	if client.SamlIdpInitiatedSsoUrlName != nil {
		attributes[SamlIdpInitiatedSsoUrlName] = *client.SamlIdpInitiatedSsoUrlName
	}
	if client.SamlIdpInitiatedSsoRelayState != nil {
		attributes[SamlIdpInitiatedSsoRelayState] = *client.SamlIdpInitiatedSsoRelayState
	}
	if client.SamlNameIdFormat != nil {
		attributes[SamlNameIdFormat] = *client.SamlNameIdFormat
	}
	if client.SamlForceNameIdFormat != nil {
		attributes[SamlForceNameIdFormat] = strconv.FormatBool(*client.SamlForceNameIdFormat)
	}
	if client.SamlForcePostBinding != nil {
		attributes[SamlForcePostBinding] = strconv.FormatBool(*client.SamlForcePostBinding)
	}
	if client.SamlArtifactBinding != nil {
		attributes[SamlArtifactBinding] = strconv.FormatBool(*client.SamlArtifactBinding)
	}
	if client.SamlAuthnstatement != nil {
		attributes[SamlAuthnstatement] = strconv.FormatBool(*client.SamlAuthnstatement)
	}
	if client.SamlOnetimeuseCondition != nil {
		attributes[SamlOnetimeuseCondition] = strconv.FormatBool(*client.SamlOnetimeuseCondition)
	}
	if client.SamlServerSignatureKeyinfoExt != nil {
		attributes[SamlServerSignatureKeyinfoExt] = strconv.FormatBool(*client.SamlServerSignatureKeyinfoExt)
	}
	return attributes
}

func getAsBool(attributes map[string]string, attribute string) *bool {
	if value, found := attributes[attribute]; found {
		resultBool, _ := strconv.ParseBool(value)
		return &resultBool
	} else {
		return nil
	}
}

func getAsString(attributes map[string]string, attribute string) *string {
	if value, found := attributes[attribute]; found {
		return sPointer(value)
	} else {
		return nil
	}
}
