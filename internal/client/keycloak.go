package client

import (
	"context"
	"reflect"
	"strings"

	"github.com/Nerzal/gocloak/v12"

	"github.com/pascal-sochacki/provider-keycloak/apis/v1alpha1"
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

func (c KeycloakClient) RealmExists(name string, parameters v1alpha1.RealmParameters, config *v1alpha1.SmtpConfig) (bool, resourceUpToDate bool, err error) {
	var token *gocloak.JWT
	token, err = c.loginAdmin()
	if err != nil {
		return false, false, err

	}
	var realm *gocloak.RealmRepresentation
	realm, err = c.client.GetRealm(c.ctx, token.AccessToken, name)
	if err != nil {
		return false, false, err
	}
	resourceUpToDate = RealmUpToDate(name, parameters, config, *realm)
	return true, resourceUpToDate, nil
}

func (c KeycloakClient) CreateRealm(name string, realm v1alpha1.RealmParameters, config *v1alpha1.SmtpConfig) (*string, error) {
	var token, err = c.loginAdmin()
	if err != nil {
		return nil, err
	}
	if realm.Enabled == nil {
		enabled := true
		realm.Enabled = &enabled
	}

	var id string
	id, err = c.client.CreateRealm(c.ctx, token.AccessToken, mapRealm(name, realm, config))

	return &id, err
}

func (c KeycloakClient) UpdateRealm(name string, realm v1alpha1.RealmParameters, config *v1alpha1.SmtpConfig) error {

	var token, err = c.loginAdmin()
	if err != nil {
		return err
	}
	representation := mapRealm(name, realm, config)

	return c.client.UpdateRealm(c.ctx, token.AccessToken, representation)
}

func (c KeycloakClient) DeleteRealm(name string) error {
	var token, err = c.loginAdmin()
	if err != nil {
		return err
	}

	return c.client.DeleteRealm(c.ctx, token.AccessToken, name)
}

func (c KeycloakClient) GetClient(realm string, id string) (*v1alpha1.ClientParameters, *string, error) {
	var token *gocloak.JWT
	var err error
	token, err = c.loginAdmin()
	if err != nil {
		return nil, nil, err

	}
	var client *gocloak.Client
	client, err = c.client.GetClient(c.ctx, token.AccessToken, realm, id)
	if err != nil {
		return nil, nil, err
	}
	_, result := mapClientBack(*client, realm)
	return &result, client.Secret, err
}

func (c KeycloakClient) CreateClient(realm string, id string, client v1alpha1.ClientParameters) (*string, error) {
	var token, err = c.loginAdmin()
	if err != nil {
		return nil, err
	}
	newClient := mapClient(id, client)
	var createdId string
	createdId, err = c.client.CreateClient(c.ctx, token.AccessToken, realm, newClient)
	return &createdId, err
}

func mapClient(id string, client v1alpha1.ClientParameters) gocloak.Client {
	var attributes = map[string]string{}

	if client.ValidPostLogoutUris != nil {
		attributes["post.logout.redirect.uris"] = strings.Join(*client.ValidPostLogoutUris, "##")
	}

	return gocloak.Client{
		ID: &id,

		Name:         client.Name,
		Protocol:     &client.Protocol,
		Description:  client.Description,
		RootURL:      client.RootUrl,
		BaseURL:      client.HomeUrl,
		RedirectURIs: client.ValidRedirectUris,
		Attributes:   &attributes,
		AdminURL:     client.AdminUrl,
		WebOrigins:   client.WebOrigins,
	}
}

func mapClientBack(client gocloak.Client, realm string) (id string, result v1alpha1.ClientParameters) {
	attributes := *client.Attributes
	var uris *[]string
	if attributes != nil {
		uriString := attributes["post.logout.redirect.uris"]
		urisplit := strings.Split(uriString, "##")
		uris = &urisplit
	}
	return *client.ClientID, v1alpha1.ClientParameters{
		Realm: realm,

		Name:                client.Name,
		Protocol:            *client.Protocol,
		Description:         client.Description,
		RootUrl:             client.RootURL,
		HomeUrl:             client.BaseURL,
		ValidRedirectUris:   client.RedirectURIs,
		ValidPostLogoutUris: uris,
		AdminUrl:            client.AdminURL,
		WebOrigins:          client.WebOrigins,
	}
}

func (c KeycloakClient) UpdateClient(realm string, id string, client v1alpha1.ClientParameters) error {
	var token, err = c.loginAdmin()
	if err != nil {
		return err
	}
	update := mapClient(id, client)
	return c.client.UpdateClient(c.ctx, token.AccessToken, realm, update)
}

func (c KeycloakClient) DeleteClient(realm string, id string) error {
	var token, err = c.loginAdmin()
	if err != nil {
		return err
	}
	return c.client.DeleteClient(c.ctx, token.AccessToken, realm, id)
}

func RealmUpToDate(desiredName string, desiredParameters v1alpha1.RealmParameters, desiredConfig *v1alpha1.SmtpConfig, representation gocloak.RealmRepresentation) bool {
	var config *v1alpha1.SmtpConfig
	var parameters v1alpha1.RealmParameters
	var name string
	name, parameters, config = mapBackRealm(representation)

	if name != desiredName {
		return false
	}

	if config != nil {
		config.Password = ""
	}
	if desiredConfig != nil {
		desiredConfig.Password = ""
	} else {
		desiredConfig = &v1alpha1.SmtpConfig{
			From:               "",
			FromDisplayName:    "",
			ReplyTo:            "",
			ReplyToDisplayName: "",
			EnvelopeFrom:       "",
			Host:               "",
			Port:               "",
			Ssl:                "",
			StartTls:           "",
			Auth:               "",
			User:               "",
			Password:           "",
		}
	}

	if !reflect.DeepEqual(config, desiredConfig) {
		return false
	}

	parameters.SmtpCredentials = nil
	desiredParameters.SmtpCredentials = nil

	// there are some additional attributes from keycloak and I don't know how to handle this
	parameters.Attributes = nil
	desiredParameters.Attributes = nil

	if !reflect.DeepEqual(parameters.BruteForceDetection, desiredParameters.BruteForceDetection) {
		return false
	}

	if !reflect.DeepEqual(parameters.OTPPolicy, desiredParameters.OTPPolicy) {
		return false
	}

	if !reflect.DeepEqual(parameters.WebAuthnPolicy, desiredParameters.WebAuthnPolicy) {
		return false
	}

	if !reflect.DeepEqual(parameters.WebAuthnPasswordlessPolicy, desiredParameters.WebAuthnPasswordlessPolicy) {
		return false
	}

	return reflect.DeepEqual(parameters, desiredParameters)
}

func mapRealm(name string, realm v1alpha1.RealmParameters, smtpCredentials *v1alpha1.SmtpConfig) gocloak.RealmRepresentation {
	representation := gocloak.RealmRepresentation{
		Realm:                    &name,
		Enabled:                  realm.Enabled,
		DisplayName:              realm.DisplayName,
		DisplayNameHTML:          realm.DisplayNameHTML,
		UserManagedAccessAllowed: realm.UserManagedAccess,
		Attributes:               realm.Attributes,

		RegistrationAllowed:         realm.RegistrationAllowed,
		RegistrationEmailAsUsername: realm.RegistrationEmailAsUsername,
		EditUsernameAllowed:         realm.EditUsernameAllowed,
		ResetPasswordAllowed:        realm.ResetPasswordAllowed,
		RememberMe:                  realm.RememberMe,
		VerifyEmail:                 realm.VerifyEmail,
		LoginWithEmailAllowed:       realm.LoginWithEmailAllowed,
		DuplicateEmailsAllowed:      realm.DuplicateEmailsAllowed,
		SslRequired:                 realm.SSLRequired,

		DefaultSignatureAlgorithm: realm.DefaultSignatureAlgorithm,
		RevokeRefreshToken:        realm.RevokeRefreshToken,
		RefreshTokenMaxReuse:      realm.RefreshTokenMaxReuse,

		SsoSessionIdleTimeout:            realm.SSOSessionIdleTimeout,
		SsoSessionMaxLifespan:            realm.SSOSessionMaxLifespan,
		SsoSessionMaxLifespanRememberMe:  realm.SSOSessionMaxLifespanRememberMe,
		OfflineSessionIdleTimeout:        realm.OfflineSessionIdleTimeout,
		OfflineSessionMaxLifespan:        realm.OfflineSessionMaxLifespan,
		OfflineSessionMaxLifespanEnabled: realm.OfflineSessionMaxLifespanEnabled,

		AccessTokenLifespan:                 realm.AccessTokenLifespan,
		AccessTokenLifespanForImplicitFlow:  realm.AccessTokenLifespanForImplicitFlow,
		AccessCodeLifespan:                  realm.AccessCodeLifespan,
		AccessCodeLifespanLogin:             realm.AccessCodeLifespanLogin,
		AccessCodeLifespanUserAction:        realm.AccessCodeLifespanUserAction,
		ActionTokenGeneratedByUserLifespan:  realm.ActionTokenGeneratedByUserLifespan,
		ActionTokenGeneratedByAdminLifespan: realm.ActionTokenGeneratedByAdminLifespan,

		SMTPServer: &map[string]string{},

		SupportedLocales:            realm.SupportedLocales,
		DefaultLocale:               realm.DefaultLocale,
		InternationalizationEnabled: realm.InternationalizationEnabled,

		BrowserSecurityHeaders: &map[string]string{},

		PasswordPolicy: realm.PasswordPolicy,

		BrowserFlow:              realm.BrowserFlow,
		RegistrationFlow:         realm.RegistrationFlow,
		DirectGrantFlow:          realm.DirectGrantFlow,
		ResetCredentialsFlow:     realm.ResetCredentialsFlow,
		ClientAuthenticationFlow: realm.ClientAuthenticationFlow,
		DockerAuthenticationFlow: realm.DockerAuthenticationFlow,
	}

	if smtpCredentials != nil {
		server := *representation.SMTPServer
		server["password"] = smtpCredentials.Password
		server["host"] = smtpCredentials.Host
		server["auth"] = smtpCredentials.Auth
		server["port"] = smtpCredentials.Port
		server["ssl"] = smtpCredentials.Ssl
		server["starttls"] = smtpCredentials.StartTls
		server["user"] = smtpCredentials.User
		server["from"] = smtpCredentials.From
		server["fromDisplayName"] = smtpCredentials.FromDisplayName
	}

	representation.BrowserSecurityHeaders = mapHeaders(realm.Headers)

	if realm.BruteForceDetection != nil {
		enabled := true
		representation.BruteForceProtected = &enabled
		representation.FailureFactor = realm.BruteForceDetection.MaxLoginFailures
		representation.MaxDeltaTimeSeconds = realm.BruteForceDetection.FailureResetTimeSeconds

		representation.PermanentLockout = realm.BruteForceDetection.PermanentLockout

		representation.WaitIncrementSeconds = realm.BruteForceDetection.WaitIncrementSeconds
		representation.MaxFailureWaitSeconds = realm.BruteForceDetection.MaxFailureWaitSeconds
		representation.QuickLoginCheckMilliSeconds = realm.BruteForceDetection.QuickLoginCheckMilliSeconds
		representation.MinimumQuickLoginWaitSeconds = realm.BruteForceDetection.MinimumQuickLoginWaitSeconds
	}

	representation.OtpPolicyType = realm.OTPPolicy.Type
	representation.OtpPolicyAlgorithm = realm.OTPPolicy.Algorithm
	representation.OtpPolicyDigits = realm.OTPPolicy.Digits
	representation.OtpPolicyInitialCounter = realm.OTPPolicy.InitialCounter
	representation.OtpPolicyLookAheadWindow = realm.OTPPolicy.LookAheadWindow
	representation.OtpPolicyPeriod = realm.OTPPolicy.Period

	representation.WebAuthnPolicyRpEntityName = realm.WebAuthnPolicy.RelyingPartyEntityName
	representation.WebAuthnPolicyRpID = realm.WebAuthnPolicy.RelyingPartyId

	representation.WebAuthnPolicySignatureAlgorithms = mapAlgorithmBack(*realm.WebAuthnPolicy.SignatureAlgorithms)

	representation.WebAuthnPolicyAttestationConveyancePreference = realm.WebAuthnPolicy.AttestationConveyancePreference
	representation.WebAuthnPolicyAuthenticatorAttachment = realm.WebAuthnPolicy.AuthenticatorAttachment
	representation.WebAuthnPolicyRequireResidentKey = realm.WebAuthnPolicy.RequireResidentKey
	representation.WebAuthnPolicyUserVerificationRequirement = realm.WebAuthnPolicy.UserVerificationRequirement
	representation.WebAuthnPolicyCreateTimeout = realm.WebAuthnPolicy.CreateTimeout
	representation.WebAuthnPolicyAvoidSameAuthenticatorRegister = realm.WebAuthnPolicy.AvoidSameAuthenticatorRegister

	representation.WebAuthnPolicyAcceptableAaguids = realm.WebAuthnPolicy.AcceptableAaguids
	representation.WebAuthnPolicyPasswordlessRpEntityName = realm.WebAuthnPasswordlessPolicy.RelyingPartyEntityName
	representation.WebAuthnPolicyPasswordlessRpID = realm.WebAuthnPasswordlessPolicy.RelyingPartyId
	representation.WebAuthnPolicyPasswordlessSignatureAlgorithms = mapAlgorithmBack(*realm.WebAuthnPasswordlessPolicy.SignatureAlgorithms)
	representation.WebAuthnPolicyPasswordlessAttestationConveyancePreference = realm.WebAuthnPasswordlessPolicy.AttestationConveyancePreference
	representation.WebAuthnPolicyPasswordlessAuthenticatorAttachment = realm.WebAuthnPasswordlessPolicy.AuthenticatorAttachment
	representation.WebAuthnPolicyPasswordlessRequireResidentKey = realm.WebAuthnPasswordlessPolicy.RequireResidentKey
	representation.WebAuthnPolicyPasswordlessUserVerificationRequirement = realm.WebAuthnPasswordlessPolicy.UserVerificationRequirement
	representation.WebAuthnPolicyPasswordlessCreateTimeout = realm.WebAuthnPasswordlessPolicy.CreateTimeout
	representation.WebAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister = realm.WebAuthnPasswordlessPolicy.AvoidSameAuthenticatorRegister
	representation.WebAuthnPolicyPasswordlessAcceptableAaguids = realm.WebAuthnPasswordlessPolicy.AcceptableAaguids

	return representation
}

func mapAlgorithmBack(algorithms []v1alpha1.SignatureAlgorithms) *[]string {
	mapped := make([]string, len(algorithms))
	for i := range algorithms {
		mapped[i] = string(algorithms[i])
	}
	return &mapped
}

func mapBackRealm(representation gocloak.RealmRepresentation) (name string, realm v1alpha1.RealmParameters, smtpCredentials *v1alpha1.SmtpConfig) {
	locales := representation.SupportedLocales

	headerConfig := v1alpha1.HeadersConfig{}
	if representation.BrowserSecurityHeaders != nil {
		headerConfig = mapHeadersBack(representation)
	}

	var bruteForceDetectionConfig *v1alpha1.BruteForceDetectionConfig
	if representation.BruteForceProtected != nil && *representation.BruteForceProtected {
		bruteForceDetectionConfig = &v1alpha1.BruteForceDetectionConfig{
			MaxLoginFailures:             representation.FailureFactor,
			PermanentLockout:             representation.PermanentLockout,
			WaitIncrementSeconds:         representation.WaitIncrementSeconds,
			MaxFailureWaitSeconds:        representation.MaxFailureWaitSeconds,
			FailureResetTimeSeconds:      representation.MaxDeltaTimeSeconds,
			QuickLoginCheckMilliSeconds:  representation.QuickLoginCheckMilliSeconds,
			MinimumQuickLoginWaitSeconds: representation.MinimumQuickLoginWaitSeconds,
		}
	}

	var otpPolicyConfig = v1alpha1.OTPPolicyConfig{
		Type:            representation.OtpPolicyType,
		Algorithm:       representation.OtpPolicyAlgorithm,
		Digits:          representation.OtpPolicyDigits,
		InitialCounter:  representation.OtpPolicyInitialCounter,
		LookAheadWindow: representation.OtpPolicyLookAheadWindow,
		Period:          representation.OtpPolicyPeriod,
	}

	if locales != nil && len(*locales) == 0 {
		locales = nil
	}

	WebAuthnPolicy := mapWebAuthnPolicy(representation)
	WebAuthnPasswordlessPolicy := mapWebAuthnPasswordlessPolicy(representation)

	parameters := v1alpha1.RealmParameters{
		Enabled:                     representation.Enabled,
		DisplayName:                 representation.DisplayName,
		DisplayNameHTML:             representation.DisplayNameHTML,
		UserManagedAccess:           representation.UserManagedAccessAllowed,
		Attributes:                  representation.Attributes,
		RegistrationAllowed:         representation.RegistrationAllowed,
		RegistrationEmailAsUsername: representation.RegistrationEmailAsUsername,
		EditUsernameAllowed:         representation.EditUsernameAllowed,
		ResetPasswordAllowed:        representation.ResetPasswordAllowed,
		RememberMe:                  representation.RememberMe,
		VerifyEmail:                 representation.VerifyEmail,
		LoginWithEmailAllowed:       representation.LoginWithEmailAllowed,
		DuplicateEmailsAllowed:      representation.DuplicateEmailsAllowed,
		SSLRequired:                 representation.SslRequired,

		DefaultSignatureAlgorithm: representation.DefaultSignatureAlgorithm,
		RevokeRefreshToken:        representation.RevokeRefreshToken,
		RefreshTokenMaxReuse:      representation.RefreshTokenMaxReuse,

		SSOSessionIdleTimeout:            representation.SsoSessionIdleTimeout,
		SSOSessionMaxLifespan:            representation.SsoSessionMaxLifespan,
		SSOSessionMaxLifespanRememberMe:  representation.SsoSessionMaxLifespanRememberMe,
		OfflineSessionIdleTimeout:        representation.OfflineSessionIdleTimeout,
		OfflineSessionMaxLifespan:        representation.OfflineSessionMaxLifespan,
		OfflineSessionMaxLifespanEnabled: representation.OfflineSessionMaxLifespanEnabled,

		AccessTokenLifespan:                 representation.AccessTokenLifespan,
		AccessTokenLifespanForImplicitFlow:  representation.AccessTokenLifespanForImplicitFlow,
		AccessCodeLifespan:                  representation.AccessCodeLifespan,
		AccessCodeLifespanLogin:             representation.AccessCodeLifespanLogin,
		AccessCodeLifespanUserAction:        representation.AccessCodeLifespanUserAction,
		ActionTokenGeneratedByUserLifespan:  representation.ActionTokenGeneratedByUserLifespan,
		ActionTokenGeneratedByAdminLifespan: representation.ActionTokenGeneratedByAdminLifespan,

		SupportedLocales:            locales,
		DefaultLocale:               representation.DefaultLocale,
		InternationalizationEnabled: representation.InternationalizationEnabled,

		Headers: headerConfig,

		BruteForceDetection: bruteForceDetectionConfig,

		OTPPolicy: otpPolicyConfig,

		PasswordPolicy: representation.PasswordPolicy,

		BrowserFlow:              representation.BrowserFlow,
		RegistrationFlow:         representation.RegistrationFlow,
		DirectGrantFlow:          representation.DirectGrantFlow,
		ResetCredentialsFlow:     representation.ResetCredentialsFlow,
		ClientAuthenticationFlow: representation.ClientAuthenticationFlow,
		DockerAuthenticationFlow: representation.DockerAuthenticationFlow,

		WebAuthnPolicy:             WebAuthnPolicy,
		WebAuthnPasswordlessPolicy: WebAuthnPasswordlessPolicy,
	}

	if representation.SMTPServer != nil {
		config := v1alpha1.SmtpConfig{
			Password:        (*representation.SMTPServer)["password"],
			Host:            (*representation.SMTPServer)["host"],
			Auth:            (*representation.SMTPServer)["auth"],
			Port:            (*representation.SMTPServer)["port"],
			Ssl:             (*representation.SMTPServer)["ssl"],
			StartTls:        (*representation.SMTPServer)["starttls"],
			User:            (*representation.SMTPServer)["user"],
			From:            (*representation.SMTPServer)["from"],
			FromDisplayName: (*representation.SMTPServer)["fromDisplayName"],
		}
		return *representation.Realm, parameters, &config
	} else {
		return *representation.Realm, parameters, nil
	}
}

func mapWebAuthnPasswordlessPolicy(representation gocloak.RealmRepresentation) v1alpha1.PolicyConfig {
	WebAuthnPasswordlessPolicy := v1alpha1.PolicyConfig{
		RelyingPartyEntityName:          representation.WebAuthnPolicyPasswordlessRpEntityName,
		RelyingPartyId:                  representation.WebAuthnPolicyPasswordlessRpID,
		SignatureAlgorithms:             mapAlgorithm(representation.WebAuthnPolicyPasswordlessSignatureAlgorithms),
		AttestationConveyancePreference: representation.WebAuthnPolicyPasswordlessAttestationConveyancePreference,
		AuthenticatorAttachment:         representation.WebAuthnPolicyPasswordlessAuthenticatorAttachment,
		RequireResidentKey:              representation.WebAuthnPolicyPasswordlessRequireResidentKey,
		UserVerificationRequirement:     representation.WebAuthnPolicyPasswordlessUserVerificationRequirement,
		CreateTimeout:                   representation.WebAuthnPolicyPasswordlessCreateTimeout,
		AvoidSameAuthenticatorRegister:  representation.WebAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister,
		AcceptableAaguids:               representation.WebAuthnPolicyPasswordlessAcceptableAaguids,
	}
	if WebAuthnPasswordlessPolicy.AcceptableAaguids != nil && len(*WebAuthnPasswordlessPolicy.AcceptableAaguids) == 0 {
		WebAuthnPasswordlessPolicy.AcceptableAaguids = nil
	}
	return WebAuthnPasswordlessPolicy
}

func mapWebAuthnPolicy(representation gocloak.RealmRepresentation) v1alpha1.PolicyConfig {
	WebAuthnPolicy := v1alpha1.PolicyConfig{
		RelyingPartyEntityName:          representation.WebAuthnPolicyRpEntityName,
		RelyingPartyId:                  representation.WebAuthnPolicyRpID,
		SignatureAlgorithms:             mapAlgorithm(representation.WebAuthnPolicySignatureAlgorithms),
		AttestationConveyancePreference: representation.WebAuthnPolicyAttestationConveyancePreference,
		AuthenticatorAttachment:         representation.WebAuthnPolicyAuthenticatorAttachment,
		RequireResidentKey:              representation.WebAuthnPolicyRequireResidentKey,
		UserVerificationRequirement:     representation.WebAuthnPolicyUserVerificationRequirement,
		CreateTimeout:                   representation.WebAuthnPolicyCreateTimeout,
		AvoidSameAuthenticatorRegister:  representation.WebAuthnPolicyAvoidSameAuthenticatorRegister,
		AcceptableAaguids:               representation.WebAuthnPolicyAcceptableAaguids,
	}
	if WebAuthnPolicy.AcceptableAaguids != nil && len(*WebAuthnPolicy.AcceptableAaguids) == 0 {
		WebAuthnPolicy.AcceptableAaguids = nil
	}

	return WebAuthnPolicy
}

func mapAlgorithm(algorithms *[]string) *[]v1alpha1.SignatureAlgorithms {
	if algorithms == nil {
		return &[]v1alpha1.SignatureAlgorithms{}
	}
	mapped := make([]v1alpha1.SignatureAlgorithms, len(*algorithms))
	for i := range *algorithms {
		mapped[i] = v1alpha1.SignatureAlgorithms((*algorithms)[i])
	}
	return &mapped
}

func mapHeaders(origin v1alpha1.HeadersConfig) *map[string]string {
	headers := map[string]string{
		"contentSecurityPolicyReportOnly": "",
		"xContentTypeOptions":             "",
		"xRobotsTag":                      "",
		"xFrameOptions":                   "",
		"contentSecurityPolicy":           "",
		"xXSSProtection":                  "",
		"strictTransportSecurity":         "",
	}
	if origin.ContentSecurityPolicyReportOnly != nil {
		headers["contentSecurityPolicyReportOnly"] = *origin.ContentSecurityPolicyReportOnly
	}
	if origin.XContentTypeOptions != nil {
		headers["xContentTypeOptions"] = *origin.XContentTypeOptions
	}
	if origin.XRobotsTag != nil {
		headers["xRobotsTag"] = *origin.XRobotsTag
	}
	if origin.XFrameOptions != nil {
		headers["xFrameOptions"] = *origin.XFrameOptions
	}
	if origin.ContentSecurityPolicy != nil {
		headers["contentSecurityPolicy"] = *origin.ContentSecurityPolicy
	}
	if origin.XXssProtection != nil {
		headers["xXSSProtection"] = *origin.XXssProtection
	}
	if origin.StrictTransportSecurity != nil {
		headers["strictTransportSecurity"] = *origin.StrictTransportSecurity
	}
	return &headers
}

func mapHeadersBack(representation gocloak.RealmRepresentation) v1alpha1.HeadersConfig {
	result := v1alpha1.HeadersConfig{}
	headers := *representation.BrowserSecurityHeaders

	contentSecurityPolicyReportOnly := headers["contentSecurityPolicyReportOnly"]
	result.ContentSecurityPolicyReportOnly = &contentSecurityPolicyReportOnly

	xContentTypeOptions := headers["xContentTypeOptions"]
	result.XContentTypeOptions = &xContentTypeOptions

	xRobotsTag := headers["xRobotsTag"]
	result.XRobotsTag = &xRobotsTag

	xFrameOptions := headers["xFrameOptions"]
	result.XFrameOptions = &xFrameOptions

	contentSecurityPolicy := headers["contentSecurityPolicy"]
	result.ContentSecurityPolicy = &contentSecurityPolicy

	xXSSProtection := headers["xXSSProtection"]
	result.XXssProtection = &xXSSProtection

	strictTransportSecurity := headers["strictTransportSecurity"]
	result.StrictTransportSecurity = &strictTransportSecurity
	return result
}

func (c KeycloakClient) loginAdmin() (*gocloak.JWT, error) {
	return c.client.LoginAdmin(c.ctx, c.config.Username, c.config.Password, c.config.Realm)
}
