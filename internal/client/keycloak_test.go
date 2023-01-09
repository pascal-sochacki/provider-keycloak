package client

import (
	"reflect"
	"testing"

	"github.com/Nerzal/gocloak/v12"

	"github.com/pascal-sochacki/provider-keycloak/apis/v1alpha1"
)

func TestRealmUpToDate(t *testing.T) {
	type args struct {
		name           string
		parameters     v1alpha1.RealmParameters
		config         *v1alpha1.SmtpConfig
		representation gocloak.RealmRepresentation
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Should return false because name differs",
			args: args{
				name:       "NewName",
				parameters: v1alpha1.NewRealmParameters().WithBruteForceDetection(),
				representation: gocloak.RealmRepresentation{
					Realm: NewStringPointer("oldName"),
				},
			},
			want: false,
		},
		{
			name: "Should return true because name is the same",
			args: args{
				name:       "oldName",
				parameters: v1alpha1.NewRealmParameters(),
				representation: gocloak.RealmRepresentation{
					Realm: NewStringPointer("oldName"),
					SMTPServer: &map[string]string{
						"from":               "",
						"fromDisplayName":    "",
						"replyTo":            "",
						"replyToDisplayName": "",
						"envelopeFrom":       "",
						"host":               "",
						"port":               "",
						"ssl":                "",
						"starttls":           "",
						"auth":               "",
						"user":               "",
						"password":           "",
					},
				},
			},
			want: true,
		},
		{
			name: "Should return false because smtp setting is missing",
			args: args{
				name:       "oldName",
				parameters: v1alpha1.NewRealmParameters().WithBruteForceDetection(),
				config: &v1alpha1.SmtpConfig{
					Password: "supersafe",
				},
				representation: gocloak.RealmRepresentation{
					Realm: NewStringPointer("oldName"),
				},
			},
			want: false,
		},
		{
			// We cant get the password back from keycloak, so we ignore it
			name: "Should return true because smtp password is same",
			args: args{
				name:       "oldName",
				parameters: v1alpha1.NewRealmParameters(),
				config: &v1alpha1.SmtpConfig{
					Password: "supersafe",
				},
				representation: gocloak.RealmRepresentation{
					Realm: NewStringPointer("oldName"),
					SMTPServer: &map[string]string{
						"password": "**********",
					},
				},
			},
			want: true,
		},
		{
			name: "Should return false because smtp host differs",
			args: args{
				name:       "oldName",
				parameters: v1alpha1.RealmParameters{},
				config: &v1alpha1.SmtpConfig{
					Host: "newHost",
				},
				representation: gocloak.RealmRepresentation{
					Realm: NewStringPointer("oldName"),
					SMTPServer: &map[string]string{
						"host": "oldHost",
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RealmUpToDate(tt.args.name, tt.args.parameters, tt.args.config, tt.args.representation); got != tt.want { //nolint:all
				t.Errorf("RealmUpToDate() = %v, want %v", got, tt.want) //nolint:all
			}
		})
	}
}

func Test_mapRealm(t *testing.T) {
	type args struct {
		name            string
		realm           v1alpha1.RealmParameters
		smtpCredentials *v1alpha1.SmtpConfig
	}
	tests := []struct {
		name string
		args args
		want gocloak.RealmRepresentation
	}{
		{
			name: "should map only the name",
			args: args{
				name:  "name-to-map",
				realm: v1alpha1.NewRealmParameters(),
			},
			want: gocloak.RealmRepresentation{
				Realm: NewStringPointer("name-to-map"),
				BrowserSecurityHeaders: &map[string]string{
					"contentSecurityPolicyReportOnly": "",
					"xContentTypeOptions":             "",
					"xRobotsTag":                      "",
					"xFrameOptions":                   "",
					"contentSecurityPolicy":           "",
					"xXSSProtection":                  "",
					"strictTransportSecurity":         "",
				},
				SMTPServer: &map[string]string{},
				WebAuthnPolicyPasswordlessSignatureAlgorithms: &[]string{},
				WebAuthnPolicySignatureAlgorithms:             &[]string{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			realm := mapRealm(tt.args.name, tt.args.realm, tt.args.smtpCredentials) //nolint:all
			if got := realm; !reflect.DeepEqual(got, tt.want) {                     //nolint:all
				t.Errorf("mapRealm() = %v, want %v", got, tt.want) //nolint:all
			}
		})
	}
}

func Test_mapBackRealm(t *testing.T) {
	type args struct {
		representation gocloak.RealmRepresentation
	}
	tests := []struct {
		name                string
		args                args
		wantName            string
		wantRealm           v1alpha1.RealmParameters
		wantSmtpCredentials *v1alpha1.SmtpConfig
	}{
		{
			name: "just name",
			args: args{
				representation: gocloak.RealmRepresentation{
					Realm: NewStringPointer("just-name"),
				},
			},
			wantRealm:           v1alpha1.NewRealmParameters(),
			wantName:            "just-name",
			wantSmtpCredentials: nil,
		},
		{
			name: "brute force detection",
			args: args{
				representation: gocloak.RealmRepresentation{
					Realm:               NewStringPointer("just-name"),
					BruteForceProtected: newBoolPointer(true),
				},
			},
			wantRealm:           v1alpha1.NewRealmParameters().WithBruteForceDetection(),
			wantName:            "just-name",
			wantSmtpCredentials: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotRealm, gotSmtpCredentials := mapBackRealm(tt.args.representation) //nolint:all
			if gotName != tt.wantName {                                                   //nolint:all
				t.Errorf("mapBackRealm() gotName = %v, want %v", gotName, tt.wantName) //nolint:all
			}
			if !reflect.DeepEqual(gotRealm, tt.wantRealm) { //nolint:all
				t.Errorf("mapBackRealm() gotRealm = %v, want %v", gotRealm, tt.wantRealm) //nolint:all
			}
			if !reflect.DeepEqual(gotSmtpCredentials, tt.wantSmtpCredentials) { //nolint:all
				t.Errorf("mapBackRealm() gotSmtpCredentials = %v, want %v", gotSmtpCredentials, tt.wantSmtpCredentials) //nolint:all
			}
		})
	}
}

func newBoolPointer(b bool) *bool {
	return &b
}

func NewStringPointer(value string) *string {
	return &value
}
