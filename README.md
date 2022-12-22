# provider-keycloak

Hey you found my idea to create a crossplane keycloak provider! The idea is to use the kubernetes control plane instead of other tools like terraform

## Getting Started

Do you want to see this in action?

**First create a Kubernetes Cluster and install:**
* crossplane
* keycloak

For keycloak we will use the codecentric helm chart with values to configure the admin user (see `starter` folder). 

For crossplane just run the following commands:
```shell
kubectl create namespace crossplane-system
helm repo add crossplane-stable https://charts.crossplane.io/stable
helm repo update

helm install crossplane --namespace crossplane-system crossplane-stable/crossplane
```

**Install this provider**

Just apply this yaml to your Cluster

```yaml
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: provider-keycloak
spec:
  package: "ghcr.io/pascal-sochacki/provider-keycloak:master"
```

**Create a Provider Config**

First we need to create a kubernetes secret for the keycloak user.
In the `examples/provider` folder you will find a script which creates this secret with the username and password.
After the Secret is installed you can apply the `config.yaml` in the same folder as the script.

**Create a Realm**

Now you should be able to create a Keycloak Realm! Just apply the following yaml:

```
apiVersion: realmroles.keycloak.crossplane.io/v1alpha1
kind: Realm
metadata:
  name: example
spec:
  forProvider: {}
```

If everything work you should see your Realm in a Ready and Sync State:

```
# kubectl get Realm
NAME      READY   SYNCED   EXTERNAL-NAME   AGE
example   True    True     example         3s
```
## Warning

This is far from production ready. I'm not an expert in keycloak, golang or crossplane. I hope to learn while doing this
project. Any help is highly appreciated.

## Developing

1. Use this repository as a keycloak to create a new one.
1. Run `make submodules` to initialize the "build" Make submodule we use for CI/CD.
1. Rename the provider by running the follwing command:
```
  make provider.prepare provider={PascalProviderName}
```
4. Add your new type by running the following command:
```
make provider.addtype provider={PascalProviderName} group={group} kind={type}
```
5. Replace the *sample* group with your new group in apis/{provider}.go
5. Replace the *mytype* type with your new type in internal/controller/{provider}.go
5. Replace the default controller and ProviderConfig implementations with your own
5. Run `make reviewable` to run code generation, linters, and tests.
5. Run `make build` to build the provider.

Refer to Crossplane's [CONTRIBUTING.md] file for more information on how the
Crossplane community prefers to work. The [Provider Development][provider-dev]
guide may also be of use.

[CONTRIBUTING.md]: https://github.com/crossplane/crossplane/blob/master/CONTRIBUTING.md
[provider-dev]: https://github.com/crossplane/crossplane/blob/master/docs/contributing/provider_development_guide.md
