/*
Copyright 2022 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"reflect"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// RealmParameters are the configurable fields of a Realm. A realm manages a set of users, credentials, roles, and
// groups. A user belongs to and logs into a realm. Realms are isolated from one another and can only manage and
// authenticate the users that they control.
// See https://www.keycloak.org/docs/latest/server admin/index.html#core-concepts-and-terms
type RealmParameters struct {
	// Boolean representing if realm is enabled or not
	// +kubebuilder:default=true
	Enabled *bool `json:"enabled,omitempty"`
	// +optional
	DisplayName *string `json:"displayName,omitempty"`
	// +optional
	DisplayNameHTML *string `json:"displayNameHtml,omitempty"`
	// +kubebuilder:default=false
	UserManagedAccess *bool `json:"userManagedAccess,omitempty"`
	// +optional
	Attributes *map[string]string `json:"attributes,omitempty"`

	// +kubebuilder:default=false
	RegistrationAllowed *bool `json:"registrationAllowed,omitempty"`
	// +kubebuilder:default=false
	RegistrationEmailAsUsername *bool `json:"registrationEmailAsUsername,omitempty"`
	// +kubebuilder:default=false
	EditUsernameAllowed *bool `json:"editUsernameAllowed,omitempty"`
	// +kubebuilder:default=false
	ResetPasswordAllowed *bool `json:"resetPasswordAllowed,omitempty"`
	// +kubebuilder:default=false
	RememberMe *bool `json:"rememberMe,omitempty"`
	// +kubebuilder:default=false
	VerifyEmail *bool `json:"verifyEmail,omitempty"`
	// +kubebuilder:default=true
	LoginWithEmailAllowed *bool `json:"loginWithEmailAllowed,omitempty"`
	// +kubebuilder:default=false
	DuplicateEmailsAllowed *bool `json:"duplicateEmailsAllowed,omitempty"`
	// Can be one of following values: 'none, 'external' or 'all'
	// +kubebuilder:validation:Enum=none;external;all
	// +kubebuilder:default=external
	SSLRequired *string `json:"SSLRequired,omitempty"`

	//todo: Themes

	// +kubebuilder:validation:Enum=RS256;ES256;ES384;ES512;HS256;HS384;HS512;RS256;RS384;RS512;PS256;PS384;RS512
	// +kubebuilder:default=RS256
	DefaultSignatureAlgorithm *string `json:"defaultSignatureAlgorithm,omitempty"`
	// +kubebuilder:defaul`t=false
	RevokeRefreshToken *bool `json:"revokeRefreshToken,omitempty"` // +optional
	// +kubebuilder:default=0
	RefreshTokenMaxReuse *int `json:"refreshTokenMaxReuse,omitempty"`

	// SSO Session Idle in seconds
	// +kubebuilder:default=1800
	SSOSessionIdleTimeout *int `json:"SSOSessionIdleTimeout,omitempty"`
	// SSO Session Max Lifespan in seconds
	// +kubebuilder:default=36000
	SSOSessionMaxLifespan *int `json:"SSOSessionMaxLifespan,omitempty"`
	// +kubebuilder:default=0
	SSOSessionMaxLifespanRememberMe *int `json:"SSOSessionMaxLifespanRememberMe,omitempty"`
	// +kubebuilder:default=2592000
	OfflineSessionIdleTimeout *int `json:"OfflineSessionIdleTimeout,omitempty"`
	// +kubebuilder:default=5184000
	OfflineSessionMaxLifespan *int `json:"OfflineSessionMaxLifespan,omitempty"`
	// +kubebuilder:default=false
	OfflineSessionMaxLifespanEnabled *bool `json:"OfflineSessionMaxLifespanEnabled,omitempty"`
	// +kubebuilder:default=300
	AccessTokenLifespan *int `json:"AccessTokenLifespan,omitempty"`
	// +kubebuilder:default=900
	AccessTokenLifespanForImplicitFlow *int `json:"AccessTokenLifespanForImplicitFlow,omitempty"`
	// +kubebuilder:default=60
	AccessCodeLifespan *int `json:"AccessCodeLifespan,omitempty"`
	// +kubebuilder:default=1800
	AccessCodeLifespanLogin *int `json:"AccessCodeLifespanLogin,omitempty"`
	// +kubebuilder:default=300
	AccessCodeLifespanUserAction *int `json:"AccessCodeLifespanUserAction,omitempty"`
	// +kubebuilder:default=300
	ActionTokenGeneratedByUserLifespan *int `json:"ActionTokenGeneratedByUserLifespan,omitempty"`
	// +kubebuilder:default=43200
	ActionTokenGeneratedByAdminLifespan *int `json:"ActionTokenGeneratedByAdminLifespan,omitempty"`

	// +optional
	SmtpCredentials *SmtpCredentials `json:"smtpCredentials"`

	// +optional
	SupportedLocales *[]string `json:"SupportedLocales"`
	// +optional
	DefaultLocale *string `json:"defaultLocale,omitempty"`
	// +kubebuilder:default=false
	InternationalizationEnabled *bool `json:"internationalizationEnabled,omitempty"`

	// +kubebuilder:default={XFrameOptions: "SAMEORIGIN", XRobotsTag: "none", ContentSecurityPolicyReportOnly: "", ContentSecurityPolicy: "frame-src 'self'; frame-ancestors 'self'; object-src 'none';", XContentTypeOptions: "nosniff", XXssProtection: "1; mode=block", StrictTransportSecurity: "max-age=31536000; includeSubDomains"}
	Headers HeadersConfig `json:"headers"`
	// +optional
	BruteForceDetection *BruteForceDetectionConfig `json:"bruteForceDetection,omitempty"`

	// +optional
	PasswordPolicy *string `json:"passwordPolicy,omitempty"`

	// +kubebuilder:default=browser
	BrowserFlow *string `json:"BrowserFlow,omitempty"`
	// +kubebuilder:default=registration
	RegistrationFlow *string `json:"RegistrationFlow,omitempty"`
	// +kubebuilder:default=direct grant
	DirectGrantFlow *string `json:"DirectGrantFlow,omitempty"`
	// +kubebuilder:default=reset credentials
	ResetCredentialsFlow *string `json:"ResetCredentialsFlow,omitempty"`
	// +kubebuilder:default=clients
	ClientAuthenticationFlow *string `json:"ClientAuthenticationFlow,omitempty"`
	// +kubebuilder:default=docker auth
	DockerAuthenticationFlow *string `json:"DockerAuthenticationFlow,omitempty"`

	// +kubebuilder:default={Type: "totp", Algorithm: "HmacSHA1", Digits: 6, InitialCounter: 0, LookAheadWindow: 1, Period: 30}
	OTPPolicy OTPPolicyConfig `json:"OTPPolicy,omitempty"`

	// +kubebuilder:default={RelyingPartyEntityName: "keycloak", RelyingPartyId: "", SignatureAlgorithms: {"ES256"}, AttestationConveyancePreference: "not specified", AuthenticatorAttachment: "not specified", RequireResidentKey: "not specified", UserVerificationRequirement: "not specified", CreateTimeout: 0, AvoidSameAuthenticatorRegister: false}
	WebAuthnPolicy PolicyConfig `json:"WebAuthnPolicy,omitempty"`
	// +kubebuilder:default={RelyingPartyEntityName: "keycloak", RelyingPartyId: "", SignatureAlgorithms: {"ES256"}, AttestationConveyancePreference: "not specified", AuthenticatorAttachment: "not specified", RequireResidentKey: "not specified", UserVerificationRequirement: "not specified", CreateTimeout: 0, AvoidSameAuthenticatorRegister: false}
	WebAuthnPasswordlessPolicy PolicyConfig `json:"WebAuthnPasswordlessPolicy,omitempty"`
}

// SmtpCredentials are the smtp credentials for a Realm
type SmtpCredentials struct {
	// Source of the provider credentials.
	// +kubebuilder:validation:Enum=None;Secret;InjectedIdentity;Environment;Filesystem
	Source xpv1.CredentialsSource `json:"source"`

	xpv1.CommonCredentialSelectors `json:",inline"`
}

type SmtpConfig struct {
	From               string `json:"from"`
	FromDisplayName    string `json:"fromDisplayName"`
	ReplyTo            string `json:"replyTo"`
	ReplyToDisplayName string `json:"replyToDisplayName"`
	EnvelopeFrom       string `json:"envelopeFrom"`

	Host     string `json:"host"`
	Port     string `json:"port"`
	Ssl      string `json:"ssl"`
	StartTls string `json:"starttls"`
	Auth     string `json:"auth"`
	User     string `json:"user"`
	Password string `json:"password"`
}

type HeadersConfig struct {
	XFrameOptions                   *string `json:"XFrameOptions"`
	ContentSecurityPolicy           *string `json:"ContentSecurityPolicy"`
	ContentSecurityPolicyReportOnly *string `json:"ContentSecurityPolicyReportOnly"`
	XContentTypeOptions             *string `json:"XContentTypeOptions"`
	XRobotsTag                      *string `json:"XRobotsTag"`
	XXssProtection                  *string `json:"XXssProtection"`
	StrictTransportSecurity         *string `json:"StrictTransportSecurity"`
}

type BruteForceDetectionConfig struct {
	// +kubebuilder:default=false
	PermanentLockout *bool `json:"PermanentLockout"`
	// +kubebuilder:default=30
	MaxLoginFailures *int `json:"MaxLoginFailures"`
	// +kubebuilder:default=60
	WaitIncrementSeconds *int `json:"WaitIncrementSeconds"`
	// +kubebuilder:default=1000
	QuickLoginCheckMilliSeconds *int64 `json:"QuickLoginCheckMilliSeconds"`
	// +kubebuilder:default=60
	MinimumQuickLoginWaitSeconds *int `json:"MinimumQuickLoginWaitSeconds"`
	// +kubebuilder:default=900
	MaxFailureWaitSeconds   *int `json:"MaxFailureWaitSeconds"`
	FailureResetTimeSeconds *int `json:"FailureResetTimeSeconds"`
}

type OTPPolicyConfig struct {
	// +kubebuilder:validation:Enum=totp;hotp
	Type *string `json:"Type"`
	// +kubebuilder:validation:Enum=HmacSHA1;HmacSHA256;HmacSHA512
	Algorithm *string `json:"Algorithm"`
	// +kubebuilder:validation:Enum=6;8
	Digits          *int `json:"Digits"`
	InitialCounter  *int `json:"InitialCounter"`
	LookAheadWindow *int `json:"LookAheadWindow"`
	Period          *int `json:"Period"`
}

type PolicyConfig struct {
	// +optional
	RelyingPartyEntityName *string `json:"RelyingPartyEntityName"`
	// +optional
	RelyingPartyId *string `json:"RelyingPartyId"`
	// +optional
	SignatureAlgorithms *[]SignatureAlgorithms `json:"SignatureAlgorithms"`
	// +optional
	// +kubebuilder:validation:Enum=not specified;none;indirect;direct
	AttestationConveyancePreference *string `json:"AttestationConveyancePreference"`
	// +optional
	// +kubebuilder:validation:Enum=not specified;plattform;cross-platform
	AuthenticatorAttachment *string `json:"AuthenticatorAttachment"`
	// +optional
	// +kubebuilder:validation:Enum=not specified;Yes;No
	RequireResidentKey *string `json:"RequireResidentKey"`
	// +optional
	// +kubebuilder:validation:Enum=not specified;required;preferred;discourage
	UserVerificationRequirement *string `json:"UserVerificationRequirement"`
	// The Timeout in seconds
	// +optional
	CreateTimeout *int `json:"CreateTimeout"`
	// +optional
	AvoidSameAuthenticatorRegister *bool `json:"AvoidSameAuthenticatorRegister"`
	// +optional
	AcceptableAaguids *[]string `json:"AcceptableAaguids,omitempty"`
}

// +kubebuilder:validation:Enum=ES256;ES384;ES512;RS256;RS384;RS512;RS1
type SignatureAlgorithms string

// RealmObservation are the observable fields of a Realm.
type RealmObservation struct {
	State string `json:"state"`
}

// A RealmSpec defines the desired state of a Realm.
type RealmSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       RealmParameters `json:"forProvider"`
}

// A RealmStatus represents the observed state of a Realm.
type RealmStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          RealmObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A Realm is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloak}
type Realm struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RealmSpec   `json:"spec"`
	Status RealmStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RealmList contains a list of Realm
type RealmList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Realm `json:"items"`
}

// Realm type metadata.
var (
	RealmKind             = reflect.TypeOf(Realm{}).Name()
	RealmGroupKind        = schema.GroupKind{Group: Group, Kind: RealmKind}.String()
	RealmKindAPIVersion   = RealmKind + "." + SchemeGroupVersion.String()
	RealmGroupVersionKind = SchemeGroupVersion.WithKind(RealmKind)
)

func init() {
	SchemeBuilder.Register(&Realm{}, &RealmList{})
}

func NewRealmParameters() RealmParameters {
	return RealmParameters{
		OTPPolicy:                  OTPPolicyConfig{},
		Headers:                    HeadersConfig{},
		WebAuthnPasswordlessPolicy: NewPolicyConfig(),
		WebAuthnPolicy:             NewPolicyConfig(),
	}
}

func NewPolicyConfig() PolicyConfig {
	return PolicyConfig{
		SignatureAlgorithms: &[]SignatureAlgorithms{},
	}
}

func (c RealmParameters) WithBruteForceDetection() RealmParameters {
	c.BruteForceDetection = &BruteForceDetectionConfig{}
	return c
}
