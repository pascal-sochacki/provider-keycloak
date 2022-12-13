# provider-keycloak

## Getting Started

```shell
cat << EOF > values.yaml
command:
- "/opt/keycloak/bin/kc.sh"
- "start"
- "--http-enabled=true"
- "--http-port=8080"
- "--hostname-strict=false"
- "--hostname-strict-https=false"
  extraEnv: |
- name: KEYCLOAK_ADMIN
  value: admin
- name: KEYCLOAK_ADMIN_PASSWORD
  value: admin
- name: JAVA_OPTS_APPEND
  value: >-
  -Djgroups.dns.query={{ include "keycloak.fullname" . }}-headless
  EOF
```
1. `helm install keycloak codecentric/keycloakx --values ./values.yaml`
1. `kubectl --namespace default port-forward pod/keycloak-0 8080`
1. Create the admin user in the ui http://localhost:8080/auth/ to work with the examples use admin;admin


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
