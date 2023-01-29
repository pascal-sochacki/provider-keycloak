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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

// ClientParameters are the configurable fields of a Client.
// +kubebuilder:validation:XValidation:rule="!self.AuthorizationServicesEnabled || (self.AuthorizationServicesEnabled && self.ServiceAccountsEnabled)"
// +kubebuilder:validation:XValidation:rule="(self.Protocol == 'saml') || (self.PublicClient && !has(self.ClientAuthenticatorType)) || (!self.PublicClient && has(self.ClientAuthenticatorType))"
// +kubebuilder:validation:XValidation:rule="(self.Protocol == 'saml') || (self.Protocol != 'saml' && !has(self.SamlIdpInitiatedSsoUrlName))"
// +kubebuilder:validation:XValidation:rule="(self.Protocol == 'saml') || (self.Protocol != 'saml' && !has(self.SamlIdpInitiatedSsoRelayState))"
// +kubebuilder:validation:XValidation:rule="(self.Protocol == 'saml') || (self.Protocol != 'saml' && !has(self.SamlNameIdFormat))"
// +kubebuilder:validation:XValidation:rule="(self.Protocol == 'saml') || (self.Protocol != 'saml' && !has(self.SamlForcePostBinding))"
// +kubebuilder:validation:XValidation:rule="(self.Protocol == 'saml') || (self.Protocol != 'saml' && !has(self.SamlArtifactBinding))"
// +kubebuilder:validation:XValidation:rule="(self.Protocol == 'saml') || (self.Protocol != 'saml' && !has(self.SamlAuthnstatement))"
// +kubebuilder:validation:XValidation:rule="(self.Protocol == 'saml') || (self.Protocol != 'saml' && !has(self.SamlOnetimeuseCondition))"
// +kubebuilder:validation:XValidation:rule="(self.Protocol == 'saml') || (self.Protocol != 'saml' && !has(self.SamlServerSignatureKeyinfoExt))"
type ClientParameters struct {
	Realm string `json:"Realm"`
	// +optional
	// +kubebuilder:validation:Enum=client-secret;client-x509;client-jwt;client-secret-jwt
	ClientAuthenticatorType *string `json:"ClientAuthenticatorType"`
	// +kubebuilder:validation:Enum=saml;openid-connect
	Protocol string `json:"Protocol,omitempty"`
	// +optional
	Description *string `json:"Description,omitempty"`
	// +optional
	Name *string `json:"Name,omitempty"`
	// +optional
	// +kubebuilder:validation:Pattern=`^https?:\/\/.+$`
	RootUrl *string `json:"RootUrl,omitempty"`
	// +optional
	// +kubebuilder:validation:Pattern=`^https?:\/\/.+$`
	HomeUrl *string `json:"HomeUrl,omitempty"`
	// +optional
	ValidRedirectUris *[]string `json:"ValidRedirectUris,omitempty"`
	// +optional
	ValidPostLogoutUris *[]string `json:"ValidPostLogoutUris,omitempty"`
	// +optional
	SamlIdpInitiatedSsoRelayState *string `json:"SamlIdpInitiatedSsoRelayState,omitempty"`
	// +optional
	SamlIdpInitiatedSsoUrlName *string `json:"SamlIdpInitiatedSsoUrlName,omitempty"`
	// +optional
	AdminUrl *string `json:"AdminUrl,omitempty"`
	// +optional
	// +kubebuilder:validation:Enum=username;email;transient;persistent
	SamlNameIdFormat *string `json:"SamlNameIdFormat,omitempty"`
	// +optional
	SamlForceNameIdFormat *bool `json:"SamlForceNameIdFormat,omitempty"`
	// +optional
	SamlForcePostBinding *bool `json:"SamlForcePostBinding,omitempty"`
	// +optional
	SamlArtifactBinding *bool `json:"SamlArtifactBinding,omitempty"`
	// +optional
	SamlAuthnstatement *bool `json:"SamlAuthnstatement,omitempty"`
	// +optional
	SamlOnetimeuseCondition *bool `json:"SamlOnetimeuseCondition,omitempty"`
	// +optional
	SamlServerSignatureKeyinfoExt *bool `json:"SamlServerSignatureKeyinfoExt,omitempty"`
	// +optional
	WebOrigins *[]string `json:"WebOrigins,omitempty"`
	// +kubebuilder:default=true
	PublicClient *bool `json:"PublicClient,omitempty"`
	// +kubebuilder:default=false
	AuthorizationServicesEnabled *bool `json:"AuthorizationServicesEnabled,omitempty"`
	// +kubebuilder:default=false
	ServiceAccountsEnabled *bool `json:"ServiceAccountsEnabled,omitempty"`
	// +kubebuilder:default=true
	StandardFlowEnabled *bool `json:"StandardFlowEnabled,omitempty"`
	// +kubebuilder:default=true
	DirectAccessGrantsEnabled *bool `json:"DirectAccessGrantsEnabled,omitempty"`
	// +kubebuilder:default=false
	ImplicitFlowEnabled *bool `json:"ImplicitFlowEnabled,omitempty"`
	// +kubebuilder:default=false
	Oauth2DeviceAuthorizationGrantEnabled *bool `json:"Oauth2DeviceAuthorizationGrantEnabled,omitempty"`
	// +kubebuilder:default=false
	OidcCibaGrantEnabled *bool `json:"OidcCibaGrantEnabled,omitempty"`
	// +optional
	LoginTheme *string `json:"LoginTheme,omitempty"`
	// +kubebuilder:default=false
	ConsentRequired *bool `json:"ConsentRequired,omitempty"`
	// +kubebuilder:default=false
	DisplayClientOnConsentScreen *bool `json:"DisplayClientOnConsentScreen,omitempty"`
	// +optional
	MessageOnConsentScreen *string `json:"MessageOnConsentScreen,omitempty"`
	// +kubebuilder:default=false
	FrontChannelLogout *bool `json:"FrontChannelLogout,omitempty"`
	// +kubebuilder:validation:Pattern=`^https?:\/\/.+$`
	FrontChannelLogoutUrl *string `json:"FrontChannelLogoutUrl,omitempty"`
	// +kubebuilder:validation:Pattern=`^https?:\/\/.+$`
	BackChannelLogoutUrl *string `json:"BackChannelLogoutUrl,omitempty"`
	// +kubebuilder:default=false
	BackChannelLogoutSessionRequired *bool `json:"BackChannelLogoutSessionRequired,omitempty"`
	// +kubebuilder:default=false
	BackchannelLogoutRevokeOfflineTokens *bool `json:"BackchannelLogoutRevokeOfflineTokens,omitempty"`
}

// ClientObservation are the observable fields of a Client.
type ClientObservation struct {
	ObservableField string `json:"observableField,omitempty"`
}

// A ClientSpec defines the desired state of a Client.
type ClientSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       ClientParameters `json:"forProvider"`
}

// A ClientStatus represents the observed state of a Client.
type ClientStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          ClientObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A Client is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="REALM",type="string",JSONPath=".spec.forProvider.Realm"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloak}
type Client struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClientSpec   `json:"spec"`
	Status ClientStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClientList contains a list of Client
type ClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Client `json:"items"`
}

// Client type metadata.
var (
	ClientKind             = reflect.TypeOf(Client{}).Name()
	ClientGroupKind        = schema.GroupKind{Group: GroupName, Kind: ClientKind}.String()
	ClientKindAPIVersion   = ClientKind + "." + SchemeGroupVersion.String()
	ClientGroupVersionKind = SchemeGroupVersion.WithKind(ClientKind)
)

func init() {
	SchemeBuilder.Register(&Client{}, &ClientList{})
}
