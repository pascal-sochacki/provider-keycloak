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
type ClientParameters struct {
	Realm string `json:"Realm"`
	// +kubebuilder:validation:Enum=saml;openid-connect
	Protocol string `json:"Protocol"`
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
	ClientGroupKind        = schema.GroupKind{Group: Group, Kind: ClientKind}.String()
	ClientKindAPIVersion   = ClientKind + "." + SchemeGroupVersion.String()
	ClientGroupVersionKind = SchemeGroupVersion.WithKind(ClientKind)
)

func init() {
	SchemeBuilder.Register(&Client{}, &ClientList{})
}
