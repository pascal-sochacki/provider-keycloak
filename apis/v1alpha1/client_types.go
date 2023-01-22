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
type ClientParameters struct {
	Realm string `json:"Realm"`
	// +kubebuilder:validation:Enum=saml;openid-connect
	Protocol string `json:"Protocol"`
	// +optional
	Description *string `json:"Description"`
	// +optional
	Name *string `json:"Name"`
	// +optional
	// +kubebuilder:validation:Pattern=`^https?:\/\/.+$`
	RootUrl *string `json:"RootUrl"`
	// +optional
	// +kubebuilder:validation:Pattern=`^https?:\/\/.+$`
	HomeUrl *string `json:"HomeUrl"`
	// +optional
	ValidRedirectUris *[]string `json:"ValidRedirectUris"`
	// +optional
	ValidPostLogoutUris *[]string `json:"ValidPostLogoutUris"`
	// +optional
	AdminUrl *string `json:"AdminUrl"`
	// +optional
	WebOrigins *[]string `json:"WebOrigins"`
	// +kubebuilder:default=true
	PublicClient *bool `json:"PublicClient"`
	// +kubebuilder:default=false
	AuthorizationServicesEnabled *bool `json:"AuthorizationServicesEnabled"`
	// +kubebuilder:default=false
	ServiceAccountsEnabled *bool `json:"ServiceAccountsEnabled"`
	// +kubebuilder:default=true
	StandardFlowEnabled *bool `json:"StandardFlowEnabled"`
	// +kubebuilder:default=true
	DirectAccessGrantsEnabled *bool `json:"DirectAccessGrantsEnabled"`
	// +kubebuilder:default=false
	ImplicitFlowEnabled *bool `json:"ImplicitFlowEnabled"`
	// +kubebuilder:default=false
	Oauth2DeviceAuthorizationGrantEnabled *bool `json:"Oauth2DeviceAuthorizationGrantEnabled"`
	// +kubebuilder:default=false
	OidcCibaGrantEnabled *bool `json:"OidcCibaGrantEnabled"`
	// +optional
	LoginTheme *string `json:"LoginTheme"`
	// +kubebuilder:default=false
	ConsentRequired *bool `json:"ConsentRequired"`
	// +kubebuilder:default=false
	DisplayClientOnConsentScreen *bool `json:"DisplayClientOnConsentScreen"`
	// +optional
	MessageOnConsentScreen *string `json:"MessageOnConsentScreen"`
	// +kubebuilder:default=false
	FrontChannelLogout *bool `json:"FrontChannelLogout"`
	// +optional
	// +kubebuilder:validation:Pattern=`^https?:\/\/.+$`
	FrontChannelLogoutUrl *string `json:"FrontChannelLogoutUrl"`
	// +optional
	// +kubebuilder:validation:Pattern=`^https?:\/\/.+$`
	BackChannelLogoutUrl *string `json:"BackChannelLogoutUrl"`
	// +kubebuilder:default=false
	BackChannelLogoutSessionRequired *bool `json:"BackChannelLogoutSessionRequired"`
	// +kubebuilder:default=false
	BackchannelLogoutRevokeOfflineTokens *bool `json:"BackchannelLogoutRevokeOfflineTokens"`
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
