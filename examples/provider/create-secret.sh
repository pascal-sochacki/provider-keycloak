kubectl create namespace crossplane-system
kubectl create secret generic keycloak-credentials -n crossplane-system --from-file=credentials=./credentials.json