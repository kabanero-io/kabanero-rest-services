# The Docker image in format repository:tag. Repository may contain a remote reference.
# Override in order to customize
IMAGE ?= kabanero-rest-services:latest

# Computed repository name (no tag) including repository host/path reference
REPOSITORY=$(firstword $(subst :, ,${IMAGE}))

# Internal Docker image in format repository:tag. Repository may contain an internal service reference.
# Used for external push, and internal deployment pull
# Example case:
# export IMAGE=default-route-openshift-image-registry.apps.CLUSTER.example.com/kabanero/kabanero-operator:latest
# export REGISTRY_IMAGE=default-route-openshift-image-registry.apps.CLUSTER.example.com/openshift-marketplace/kabanero-operator-registry:latest
# export INTERNAL_IMAGE=image-registry.openshift-image-registry.svc:5000/kabanero/kabanero-operator:latest
# export INTERNAL_REGISTRY_IMAGE=image-registry.openshift-image-registry.svc:5000/openshift-marketplace/kabanero-operator-registry:latest
#INTERNAL_IMAGE ?=



.PHONY: build deploy deploy-olm build-image push-image int-test-install int-test-collections int-test-uninstall

build:
	GO111MODULE=on go install ./pkg/cmd/main
#	go install ./pkg/cmd/main

build-image:
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -o build/_output/bin/kabanero-rest-services -gcflags "all=-trimpath=$(GOPATH)" -asmflags "all=-trimpath=$(GOPATH)" -ldflags "-X main.GitTag=$(TRAVIS_TAG) -X main.GitCommit=$(TRAVIS_COMMIT) -X main.GitRepoSlug=$(TRAVIS_REPO_SLUG) -X main.BuildDate=`date -u +%Y%m%d.%H%M%S`" github.com/davco01a/kabanero-rest-services/pkg/cmd/main
#	docker build -f build/Dockerfile -t ${IMAGE} .
	docker build -f build/Dockerfile -t	davco01a/kabanero-rest-services:master	.
  	

push-image:
ifneq "$(IMAGE)" "kabanero-rest-services:latest"
  # Default push.  Make sure the namespace is there in case using local registry
#	kubectl create namespace kabanero || true
	docker push $(IMAGE)

ifdef TRAVIS_TAG
  # This is a Travis tag build. Pushing using Docker tag TRAVIS_TAG
	docker tag $(IMAGE) $(REPOSITORY):$(TRAVIS_TAG)
	docker push $(REPOSITORY):$(TRAVIS_TAG)
endif

ifdef TRAVIS_BRANCH
  # This is a Travis branch build. Pushing using Docker tag TRAVIS_BRANCH
	docker tag $(IMAGE) $(REPOSITORY):$(TRAVIS_BRANCH)
	docker push $(REPOSITORY):$(TRAVIS_BRANCH)
endif
endif

#test: 
#	go test ./cmd/... ./pkg/... 

#format:
#	go fmt ./cmd/... ./pkg/...


check: format build #test



