PORT := 5000
CAAS_CLUSTER_MONITORING_VERSION=1.0.4

#############
### TESTS ###
#############


.PHONY: test-unit
test-unit:
	@echo "Running unit tests..."
	@go test -v -race -count 1 ./...

###########
### E2E ###
###########

e2e-cluster:
	@echo "Creating registry..."
	@k3d registry create registry.localhost --port $(PORT)
	@echo "Adding registry to cluster..."
	@uname | grep -q 'Darwin' && export K3D_FIX_DNS=0; k3d cluster create prometheus-auth --registry-use k3d-registry.localhost:$(PORT)

e2e-images:
	@echo "Building test image..."
	@docker build -t k3d-registry.localhost:$(PORT)/prometheus-auth:dev .
	@echo "Pushing test image..."
	@docker push k3d-registry.localhost:$(PORT)/prometheus-auth:dev
	@echo "Importing test image to cluster..."
	@k3d image import k3d-registry.localhost:$(PORT)/prometheus-auth:dev --cluster prometheus-auth

e2e-deploy:
	@echo "Deploying the kube-prometheus-stack CRDs"
	@helm template e2e-crds oci://mtr.devops.telekom.de/caas/charts/prometheus-crds | kubectl apply --server-side -f - 
	@echo "Deploying caas-cluster-monitoring..."
	@helm upgrade e2e oci://mtr.devops.telekom.de/caas/charts/caas-cluster-monitoring \
		--install \
		--namespace cattle-monitoring-system \
	  --version $(CAAS_CLUSTER_MONITORING_VERSION) \
		--create-namespace \
		--values e2e/values.yaml \
		--wait \
		--atomic

e2e-prep: e2e-cluster e2e-keys e2e-images e2e-deploy

e2e-cleanup:
	@echo "Cleaning up test env..."
	@k3d registry delete registry.localhost || echo "Deleting k3d registry failed. Continuing..."
	@helm uninstall caas-cluster-monitoring -n cattle-monitoring-system || echo "Uninstalling caas-cluster-monitoring helm release failed. Continuing..."
	@k3d cluster delete prometheus-auth || echo "Deleting k3d cluster failed. Continuing..."
	@echo "Done."
