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

package realm

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	apisv1alpha1 "github.com/pascal-sochacki/provider-keycloak/apis/v1alpha1"
	kc "github.com/pascal-sochacki/provider-keycloak/internal/controller/client"
	"github.com/pascal-sochacki/provider-keycloak/internal/controller/features"
)

const (
	errNotRealm     = "managed resource is not a Realm custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"

	errNewClient = "cannot create new Service"
)

type KeycloakService struct {
	KeycloakClient *kc.KeycloakClient
}

var (
	newKeycloakService = func(creds []byte) (KeycloakService, error) {

		var config kc.KeycloakConfig
		err := json.Unmarshal(creds, &config)
		if err != nil {
			return KeycloakService{}, err
		}

		keycloakClient, err := kc.NewKeycloakClient(config)
		return KeycloakService{
			KeycloakClient: keycloakClient,
		}, err
	}
)

// Setup adds a controller that reconciles Realm managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(apisv1alpha1.RealmGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(apisv1alpha1.RealmGroupVersionKind),
		managed.WithExternalConnecter(&connector{
			kube:         mgr.GetClient(),
			usage:        resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
			newServiceFn: newKeycloakService}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...))

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		For(&apisv1alpha1.Realm{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

// A connector is expected to produce an ExternalClient when its Connect method
// is called.
type connector struct {
	kube         client.Client
	usage        resource.Tracker
	newServiceFn func(creds []byte) (KeycloakService, error)
}

func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*apisv1alpha1.Realm)
	if !ok {
		return nil, errors.New(errNotRealm)
	}

	if err := c.usage.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	pc := &apisv1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: cr.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetPC)
	}

	cd := pc.Spec.Credentials
	data, err := resource.CommonCredentialExtractor(ctx, cd.Source, c.kube, cd.CommonCredentialSelectors)
	if err != nil {
		return nil, errors.Wrap(err, errGetCreds)
	}

	svc, err := c.newServiceFn(data)
	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}

	return &external{
		service: svc,
		kube:    c.kube,
	}, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type external struct {
	service KeycloakService
	kube    client.Client
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*apisv1alpha1.Realm)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotRealm)
	}

	config, err := c.getSmtpConfig(ctx, cr)
	if err != nil {
		return managed.ExternalObservation{ //nolint:all

		}, err
	}

	resourceExists, resourceUpToDate, err := c.service.KeycloakClient.RealmExists(mg.GetName(), cr.Spec.ForProvider, config)
	if err != nil {
		return managed.ExternalObservation{ //nolint:all
			ResourceExists: false,
		}, nil
	}

	cr.Status.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		// Return false when the external resource does not exist. This lets
		// the managed resource reconciler know that it needs to call Create to
		// (re)create the resource, or that it has successfully been deleted.
		ResourceExists: resourceExists,

		// Return false when the external resource exists, but it not up to date
		// with the desired managed resource state. This lets the managed
		// resource reconciler know that it needs to call Update.
		ResourceUpToDate: resourceUpToDate,

		// Return any details that may be required to connect to the external
		// resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) getSmtpConfig(ctx context.Context, cr *apisv1alpha1.Realm) (*apisv1alpha1.SmtpConfig, error) {
	cd := cr.Spec.ForProvider.SmtpCredentials

	if cd == nil {
		return nil, nil
	}
	data, err := resource.CommonCredentialExtractor(ctx, cd.Source, c.kube, cd.CommonCredentialSelectors)
	if err != nil {
		return nil, err
	}

	var config apisv1alpha1.SmtpConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*apisv1alpha1.Realm)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotRealm)
	}

	smtpConfig, err := c.getSmtpConfig(ctx, cr)
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	id, err := c.service.KeycloakClient.CreateRealm(mg.GetName(), cr.Spec.ForProvider, smtpConfig)

	if err != nil {
		return managed.ExternalCreation{}, err
	}
	return managed.ExternalCreation{

		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{
			"internalId": []byte(*id),
		},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*apisv1alpha1.Realm)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotRealm)
	}

	smtpConfig, err := c.getSmtpConfig(ctx, cr)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	err = c.service.KeycloakClient.UpdateRealm(mg.GetName(), cr.Spec.ForProvider, smtpConfig)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	_, ok := mg.(*apisv1alpha1.Realm)
	if !ok {
		return errors.New(errNotRealm)
	}

	return c.service.KeycloakClient.DeleteRealm(mg.GetName())
}
