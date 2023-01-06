//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright 2020 The Crossplane Authors.

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BruteForceDetectionConfig) DeepCopyInto(out *BruteForceDetectionConfig) {
	*out = *in
	if in.PermanentLockout != nil {
		in, out := &in.PermanentLockout, &out.PermanentLockout
		*out = new(bool)
		**out = **in
	}
	if in.MaxLoginFailures != nil {
		in, out := &in.MaxLoginFailures, &out.MaxLoginFailures
		*out = new(int)
		**out = **in
	}
	if in.WaitIncrementSeconds != nil {
		in, out := &in.WaitIncrementSeconds, &out.WaitIncrementSeconds
		*out = new(int)
		**out = **in
	}
	if in.QuickLoginCheckMilliSeconds != nil {
		in, out := &in.QuickLoginCheckMilliSeconds, &out.QuickLoginCheckMilliSeconds
		*out = new(int64)
		**out = **in
	}
	if in.MinimumQuickLoginWaitSeconds != nil {
		in, out := &in.MinimumQuickLoginWaitSeconds, &out.MinimumQuickLoginWaitSeconds
		*out = new(int)
		**out = **in
	}
	if in.MaxFailureWaitSeconds != nil {
		in, out := &in.MaxFailureWaitSeconds, &out.MaxFailureWaitSeconds
		*out = new(int)
		**out = **in
	}
	if in.FailureResetTimeSeconds != nil {
		in, out := &in.FailureResetTimeSeconds, &out.FailureResetTimeSeconds
		*out = new(int)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BruteForceDetectionConfig.
func (in *BruteForceDetectionConfig) DeepCopy() *BruteForceDetectionConfig {
	if in == nil {
		return nil
	}
	out := new(BruteForceDetectionConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HeadersConfig) DeepCopyInto(out *HeadersConfig) {
	*out = *in
	if in.XFrameOptions != nil {
		in, out := &in.XFrameOptions, &out.XFrameOptions
		*out = new(string)
		**out = **in
	}
	if in.ContentSecurityPolicy != nil {
		in, out := &in.ContentSecurityPolicy, &out.ContentSecurityPolicy
		*out = new(string)
		**out = **in
	}
	if in.ContentSecurityPolicyReportOnly != nil {
		in, out := &in.ContentSecurityPolicyReportOnly, &out.ContentSecurityPolicyReportOnly
		*out = new(string)
		**out = **in
	}
	if in.XContentTypeOptions != nil {
		in, out := &in.XContentTypeOptions, &out.XContentTypeOptions
		*out = new(string)
		**out = **in
	}
	if in.XRobotsTag != nil {
		in, out := &in.XRobotsTag, &out.XRobotsTag
		*out = new(string)
		**out = **in
	}
	if in.XXssProtection != nil {
		in, out := &in.XXssProtection, &out.XXssProtection
		*out = new(string)
		**out = **in
	}
	if in.StrictTransportSecurity != nil {
		in, out := &in.StrictTransportSecurity, &out.StrictTransportSecurity
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HeadersConfig.
func (in *HeadersConfig) DeepCopy() *HeadersConfig {
	if in == nil {
		return nil
	}
	out := new(HeadersConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OTPPolicyConfig) DeepCopyInto(out *OTPPolicyConfig) {
	*out = *in
	if in.Type != nil {
		in, out := &in.Type, &out.Type
		*out = new(string)
		**out = **in
	}
	if in.Algorithm != nil {
		in, out := &in.Algorithm, &out.Algorithm
		*out = new(string)
		**out = **in
	}
	if in.Digits != nil {
		in, out := &in.Digits, &out.Digits
		*out = new(int)
		**out = **in
	}
	if in.InitialCounter != nil {
		in, out := &in.InitialCounter, &out.InitialCounter
		*out = new(int)
		**out = **in
	}
	if in.LookAheadWindow != nil {
		in, out := &in.LookAheadWindow, &out.LookAheadWindow
		*out = new(int)
		**out = **in
	}
	if in.Period != nil {
		in, out := &in.Period, &out.Period
		*out = new(int)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OTPPolicyConfig.
func (in *OTPPolicyConfig) DeepCopy() *OTPPolicyConfig {
	if in == nil {
		return nil
	}
	out := new(OTPPolicyConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyConfig) DeepCopyInto(out *PolicyConfig) {
	*out = *in
	if in.RelyingPartyEntityName != nil {
		in, out := &in.RelyingPartyEntityName, &out.RelyingPartyEntityName
		*out = new(string)
		**out = **in
	}
	if in.RelyingPartyId != nil {
		in, out := &in.RelyingPartyId, &out.RelyingPartyId
		*out = new(string)
		**out = **in
	}
	if in.SignatureAlgorithms != nil {
		in, out := &in.SignatureAlgorithms, &out.SignatureAlgorithms
		*out = new([]SignatureAlgorithms)
		if **in != nil {
			in, out := *in, *out
			*out = make([]SignatureAlgorithms, len(*in))
			copy(*out, *in)
		}
	}
	if in.AttestationConveyancePreference != nil {
		in, out := &in.AttestationConveyancePreference, &out.AttestationConveyancePreference
		*out = new(string)
		**out = **in
	}
	if in.AuthenticatorAttachment != nil {
		in, out := &in.AuthenticatorAttachment, &out.AuthenticatorAttachment
		*out = new(string)
		**out = **in
	}
	if in.RequireResidentKey != nil {
		in, out := &in.RequireResidentKey, &out.RequireResidentKey
		*out = new(string)
		**out = **in
	}
	if in.UserVerificationRequirement != nil {
		in, out := &in.UserVerificationRequirement, &out.UserVerificationRequirement
		*out = new(string)
		**out = **in
	}
	if in.CreateTimeout != nil {
		in, out := &in.CreateTimeout, &out.CreateTimeout
		*out = new(int)
		**out = **in
	}
	if in.AvoidSameAuthenticatorRegister != nil {
		in, out := &in.AvoidSameAuthenticatorRegister, &out.AvoidSameAuthenticatorRegister
		*out = new(bool)
		**out = **in
	}
	if in.AcceptableAaguids != nil {
		in, out := &in.AcceptableAaguids, &out.AcceptableAaguids
		*out = new([]string)
		if **in != nil {
			in, out := *in, *out
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyConfig.
func (in *PolicyConfig) DeepCopy() *PolicyConfig {
	if in == nil {
		return nil
	}
	out := new(PolicyConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProviderConfig) DeepCopyInto(out *ProviderConfig) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProviderConfig.
func (in *ProviderConfig) DeepCopy() *ProviderConfig {
	if in == nil {
		return nil
	}
	out := new(ProviderConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ProviderConfig) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProviderConfigList) DeepCopyInto(out *ProviderConfigList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ProviderConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProviderConfigList.
func (in *ProviderConfigList) DeepCopy() *ProviderConfigList {
	if in == nil {
		return nil
	}
	out := new(ProviderConfigList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ProviderConfigList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProviderConfigSpec) DeepCopyInto(out *ProviderConfigSpec) {
	*out = *in
	in.Credentials.DeepCopyInto(&out.Credentials)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProviderConfigSpec.
func (in *ProviderConfigSpec) DeepCopy() *ProviderConfigSpec {
	if in == nil {
		return nil
	}
	out := new(ProviderConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProviderConfigStatus) DeepCopyInto(out *ProviderConfigStatus) {
	*out = *in
	in.ProviderConfigStatus.DeepCopyInto(&out.ProviderConfigStatus)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProviderConfigStatus.
func (in *ProviderConfigStatus) DeepCopy() *ProviderConfigStatus {
	if in == nil {
		return nil
	}
	out := new(ProviderConfigStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProviderConfigUsage) DeepCopyInto(out *ProviderConfigUsage) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.ProviderConfigUsage.DeepCopyInto(&out.ProviderConfigUsage)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProviderConfigUsage.
func (in *ProviderConfigUsage) DeepCopy() *ProviderConfigUsage {
	if in == nil {
		return nil
	}
	out := new(ProviderConfigUsage)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ProviderConfigUsage) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProviderConfigUsageList) DeepCopyInto(out *ProviderConfigUsageList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ProviderConfigUsage, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProviderConfigUsageList.
func (in *ProviderConfigUsageList) DeepCopy() *ProviderConfigUsageList {
	if in == nil {
		return nil
	}
	out := new(ProviderConfigUsageList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ProviderConfigUsageList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProviderCredentials) DeepCopyInto(out *ProviderCredentials) {
	*out = *in
	in.CommonCredentialSelectors.DeepCopyInto(&out.CommonCredentialSelectors)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProviderCredentials.
func (in *ProviderCredentials) DeepCopy() *ProviderCredentials {
	if in == nil {
		return nil
	}
	out := new(ProviderCredentials)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Realm) DeepCopyInto(out *Realm) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Realm.
func (in *Realm) DeepCopy() *Realm {
	if in == nil {
		return nil
	}
	out := new(Realm)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Realm) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RealmList) DeepCopyInto(out *RealmList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Realm, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RealmList.
func (in *RealmList) DeepCopy() *RealmList {
	if in == nil {
		return nil
	}
	out := new(RealmList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RealmList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RealmObservation) DeepCopyInto(out *RealmObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RealmObservation.
func (in *RealmObservation) DeepCopy() *RealmObservation {
	if in == nil {
		return nil
	}
	out := new(RealmObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RealmParameters) DeepCopyInto(out *RealmParameters) {
	*out = *in
	if in.Enabled != nil {
		in, out := &in.Enabled, &out.Enabled
		*out = new(bool)
		**out = **in
	}
	if in.DisplayName != nil {
		in, out := &in.DisplayName, &out.DisplayName
		*out = new(string)
		**out = **in
	}
	if in.DisplayNameHTML != nil {
		in, out := &in.DisplayNameHTML, &out.DisplayNameHTML
		*out = new(string)
		**out = **in
	}
	if in.UserManagedAccess != nil {
		in, out := &in.UserManagedAccess, &out.UserManagedAccess
		*out = new(bool)
		**out = **in
	}
	if in.Attributes != nil {
		in, out := &in.Attributes, &out.Attributes
		*out = new(map[string]string)
		if **in != nil {
			in, out := *in, *out
			*out = make(map[string]string, len(*in))
			for key, val := range *in {
				(*out)[key] = val
			}
		}
	}
	if in.RegistrationAllowed != nil {
		in, out := &in.RegistrationAllowed, &out.RegistrationAllowed
		*out = new(bool)
		**out = **in
	}
	if in.RegistrationEmailAsUsername != nil {
		in, out := &in.RegistrationEmailAsUsername, &out.RegistrationEmailAsUsername
		*out = new(bool)
		**out = **in
	}
	if in.EditUsernameAllowed != nil {
		in, out := &in.EditUsernameAllowed, &out.EditUsernameAllowed
		*out = new(bool)
		**out = **in
	}
	if in.ResetPasswordAllowed != nil {
		in, out := &in.ResetPasswordAllowed, &out.ResetPasswordAllowed
		*out = new(bool)
		**out = **in
	}
	if in.RememberMe != nil {
		in, out := &in.RememberMe, &out.RememberMe
		*out = new(bool)
		**out = **in
	}
	if in.VerifyEmail != nil {
		in, out := &in.VerifyEmail, &out.VerifyEmail
		*out = new(bool)
		**out = **in
	}
	if in.LoginWithEmailAllowed != nil {
		in, out := &in.LoginWithEmailAllowed, &out.LoginWithEmailAllowed
		*out = new(bool)
		**out = **in
	}
	if in.DuplicateEmailsAllowed != nil {
		in, out := &in.DuplicateEmailsAllowed, &out.DuplicateEmailsAllowed
		*out = new(bool)
		**out = **in
	}
	if in.SSLRequired != nil {
		in, out := &in.SSLRequired, &out.SSLRequired
		*out = new(string)
		**out = **in
	}
	if in.DefaultSignatureAlgorithm != nil {
		in, out := &in.DefaultSignatureAlgorithm, &out.DefaultSignatureAlgorithm
		*out = new(string)
		**out = **in
	}
	if in.RevokeRefreshToken != nil {
		in, out := &in.RevokeRefreshToken, &out.RevokeRefreshToken
		*out = new(bool)
		**out = **in
	}
	if in.RefreshTokenMaxReuse != nil {
		in, out := &in.RefreshTokenMaxReuse, &out.RefreshTokenMaxReuse
		*out = new(int)
		**out = **in
	}
	if in.SSOSessionIdleTimeout != nil {
		in, out := &in.SSOSessionIdleTimeout, &out.SSOSessionIdleTimeout
		*out = new(int)
		**out = **in
	}
	if in.SSOSessionMaxLifespan != nil {
		in, out := &in.SSOSessionMaxLifespan, &out.SSOSessionMaxLifespan
		*out = new(int)
		**out = **in
	}
	if in.SSOSessionMaxLifespanRememberMe != nil {
		in, out := &in.SSOSessionMaxLifespanRememberMe, &out.SSOSessionMaxLifespanRememberMe
		*out = new(int)
		**out = **in
	}
	if in.OfflineSessionIdleTimeout != nil {
		in, out := &in.OfflineSessionIdleTimeout, &out.OfflineSessionIdleTimeout
		*out = new(int)
		**out = **in
	}
	if in.OfflineSessionMaxLifespan != nil {
		in, out := &in.OfflineSessionMaxLifespan, &out.OfflineSessionMaxLifespan
		*out = new(int)
		**out = **in
	}
	if in.OfflineSessionMaxLifespanEnabled != nil {
		in, out := &in.OfflineSessionMaxLifespanEnabled, &out.OfflineSessionMaxLifespanEnabled
		*out = new(bool)
		**out = **in
	}
	if in.AccessTokenLifespan != nil {
		in, out := &in.AccessTokenLifespan, &out.AccessTokenLifespan
		*out = new(int)
		**out = **in
	}
	if in.AccessTokenLifespanForImplicitFlow != nil {
		in, out := &in.AccessTokenLifespanForImplicitFlow, &out.AccessTokenLifespanForImplicitFlow
		*out = new(int)
		**out = **in
	}
	if in.AccessCodeLifespan != nil {
		in, out := &in.AccessCodeLifespan, &out.AccessCodeLifespan
		*out = new(int)
		**out = **in
	}
	if in.AccessCodeLifespanLogin != nil {
		in, out := &in.AccessCodeLifespanLogin, &out.AccessCodeLifespanLogin
		*out = new(int)
		**out = **in
	}
	if in.AccessCodeLifespanUserAction != nil {
		in, out := &in.AccessCodeLifespanUserAction, &out.AccessCodeLifespanUserAction
		*out = new(int)
		**out = **in
	}
	if in.ActionTokenGeneratedByUserLifespan != nil {
		in, out := &in.ActionTokenGeneratedByUserLifespan, &out.ActionTokenGeneratedByUserLifespan
		*out = new(int)
		**out = **in
	}
	if in.ActionTokenGeneratedByAdminLifespan != nil {
		in, out := &in.ActionTokenGeneratedByAdminLifespan, &out.ActionTokenGeneratedByAdminLifespan
		*out = new(int)
		**out = **in
	}
	if in.SmtpCredentials != nil {
		in, out := &in.SmtpCredentials, &out.SmtpCredentials
		*out = new(SmtpCredentials)
		(*in).DeepCopyInto(*out)
	}
	if in.SupportedLocales != nil {
		in, out := &in.SupportedLocales, &out.SupportedLocales
		*out = new([]string)
		if **in != nil {
			in, out := *in, *out
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
	}
	if in.DefaultLocale != nil {
		in, out := &in.DefaultLocale, &out.DefaultLocale
		*out = new(string)
		**out = **in
	}
	if in.InternationalizationEnabled != nil {
		in, out := &in.InternationalizationEnabled, &out.InternationalizationEnabled
		*out = new(bool)
		**out = **in
	}
	in.Headers.DeepCopyInto(&out.Headers)
	if in.BruteForceDetection != nil {
		in, out := &in.BruteForceDetection, &out.BruteForceDetection
		*out = new(BruteForceDetectionConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.PasswordPolicy != nil {
		in, out := &in.PasswordPolicy, &out.PasswordPolicy
		*out = new(string)
		**out = **in
	}
	if in.BrowserFlow != nil {
		in, out := &in.BrowserFlow, &out.BrowserFlow
		*out = new(string)
		**out = **in
	}
	if in.RegistrationFlow != nil {
		in, out := &in.RegistrationFlow, &out.RegistrationFlow
		*out = new(string)
		**out = **in
	}
	if in.DirectGrantFlow != nil {
		in, out := &in.DirectGrantFlow, &out.DirectGrantFlow
		*out = new(string)
		**out = **in
	}
	if in.ResetCredentialsFlow != nil {
		in, out := &in.ResetCredentialsFlow, &out.ResetCredentialsFlow
		*out = new(string)
		**out = **in
	}
	if in.ClientAuthenticationFlow != nil {
		in, out := &in.ClientAuthenticationFlow, &out.ClientAuthenticationFlow
		*out = new(string)
		**out = **in
	}
	if in.DockerAuthenticationFlow != nil {
		in, out := &in.DockerAuthenticationFlow, &out.DockerAuthenticationFlow
		*out = new(string)
		**out = **in
	}
	in.OTPPolicy.DeepCopyInto(&out.OTPPolicy)
	in.WebAuthnPolicy.DeepCopyInto(&out.WebAuthnPolicy)
	in.WebAuthnPasswordlessPolicy.DeepCopyInto(&out.WebAuthnPasswordlessPolicy)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RealmParameters.
func (in *RealmParameters) DeepCopy() *RealmParameters {
	if in == nil {
		return nil
	}
	out := new(RealmParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RealmSpec) DeepCopyInto(out *RealmSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RealmSpec.
func (in *RealmSpec) DeepCopy() *RealmSpec {
	if in == nil {
		return nil
	}
	out := new(RealmSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RealmStatus) DeepCopyInto(out *RealmStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	out.AtProvider = in.AtProvider
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RealmStatus.
func (in *RealmStatus) DeepCopy() *RealmStatus {
	if in == nil {
		return nil
	}
	out := new(RealmStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SmtpConfig) DeepCopyInto(out *SmtpConfig) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SmtpConfig.
func (in *SmtpConfig) DeepCopy() *SmtpConfig {
	if in == nil {
		return nil
	}
	out := new(SmtpConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SmtpCredentials) DeepCopyInto(out *SmtpCredentials) {
	*out = *in
	in.CommonCredentialSelectors.DeepCopyInto(&out.CommonCredentialSelectors)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SmtpCredentials.
func (in *SmtpCredentials) DeepCopy() *SmtpCredentials {
	if in == nil {
		return nil
	}
	out := new(SmtpCredentials)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *StoreConfig) DeepCopyInto(out *StoreConfig) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new StoreConfig.
func (in *StoreConfig) DeepCopy() *StoreConfig {
	if in == nil {
		return nil
	}
	out := new(StoreConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *StoreConfig) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *StoreConfigList) DeepCopyInto(out *StoreConfigList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]StoreConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new StoreConfigList.
func (in *StoreConfigList) DeepCopy() *StoreConfigList {
	if in == nil {
		return nil
	}
	out := new(StoreConfigList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *StoreConfigList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *StoreConfigSpec) DeepCopyInto(out *StoreConfigSpec) {
	*out = *in
	in.SecretStoreConfig.DeepCopyInto(&out.SecretStoreConfig)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new StoreConfigSpec.
func (in *StoreConfigSpec) DeepCopy() *StoreConfigSpec {
	if in == nil {
		return nil
	}
	out := new(StoreConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *StoreConfigStatus) DeepCopyInto(out *StoreConfigStatus) {
	*out = *in
	in.ConditionedStatus.DeepCopyInto(&out.ConditionedStatus)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new StoreConfigStatus.
func (in *StoreConfigStatus) DeepCopy() *StoreConfigStatus {
	if in == nil {
		return nil
	}
	out := new(StoreConfigStatus)
	in.DeepCopyInto(out)
	return out
}
