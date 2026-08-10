SHELL := /bin/sh

.PHONY: fmt build-manager build-agent agent-check dev dev-full dev-bundle dev-custom-bundle dev-agent-bundle dev-down dev-db-logs prepare deploy pull prepare-dev deploy-dev pull-dev down logs e2e e2e-debian12 e2e-up e2e-verify e2e-status e2e-logs e2e-down e2e-remote e2e-remote-verify e2e-remote-down

MWAF_E2E_REMOTE_ADMIN_URL ?= https://192.168.7.200:18443
MWAF_E2E_REMOTE_CA_CERT ?= deploy/compose/secrets/mwaf_ca_cert.pem
MWAF_E2E_REMOTE_RUNTIME_DIR ?= .local/mwaf-e2e-192-168-7-200
MWAF_E2E_REMOTE_PROJECT ?= mwaf-e2e-192-168-7-200
MWAF_E2E_DEBIAN12_IMAGE ?= docker.io/library/debian:12-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

fmt:
	gofmt -w cmd internal migrations web/assets.go

build-manager:
	mkdir -p bin
	go build -trimpath -o bin/mwaf-manager ./cmd/mwaf-manager

build-agent:
	mkdir -p bin
	go build -trimpath -o bin/mwaf-agent ./cmd/mwaf-agent

agent-check:
	sh scripts/check-agent-version.sh
	go test ./internal/agent ./internal/model ./internal/protocol
	go vet ./cmd/mwaf-agent ./internal/agent ./internal/model ./internal/protocol
	sh -n packaging/agent/mwaf-agent-updater packaging/agent/container/mwaf-agent-service packaging/agent/deb/build.sh internal/manager/bootstrap-install.sh

dev:
	sh ./deploy/compose/run-local.sh

dev-bundle:
	sh ./deploy/compose/build-local-bundle.sh

dev-custom-bundle:
	MWAF_DEV_CUSTOM_SOURCE_DIR="$(MWAF_DEV_CUSTOM_SOURCE_DIR)" sh ./deploy/compose/build-local-custom-bundle.sh

dev-agent-bundle:
	MWAF_DEV_AGENT_ONLY=true sh ./deploy/compose/build-local-bundle.sh

dev-full: dev-bundle
	MWAF_DEV_BUNDLE_MODE=local MWAF_DB_MIGRATE=false sh ./deploy/compose/run-local.sh

dev-down:
	sh ./deploy/compose/run-local.sh down

dev-db-logs:
	sh ./deploy/compose/run-local.sh db-logs

prepare:
	./deploy/compose/prepare.sh

pull: prepare
	docker compose --env-file deploy/compose/.env -f deploy/compose/compose.yaml pull

deploy: prepare
	docker compose --env-file deploy/compose/.env -f deploy/compose/compose.yaml up -d

prepare-dev: prepare

pull-dev: pull

deploy-dev: deploy

down:
	docker compose --env-file deploy/compose/.env -f deploy/compose/compose.yaml down

logs:
	docker compose --env-file deploy/compose/.env -f deploy/compose/compose.yaml logs -f --tail=200

e2e:
	./deploy/e2e/run.sh all

e2e-debian12:
	MWAF_E2E_RUNTIME_DIR=".local/mwaf-e2e-debian12" MWAF_E2E_PROJECT_NAME="mwaf-e2e-debian12" ./deploy/e2e/run.sh all --customer-image "$(MWAF_E2E_DEBIAN12_IMAGE)"

e2e-up:
	./deploy/e2e/run.sh up

e2e-verify:
	./deploy/e2e/run.sh verify

e2e-status:
	./deploy/e2e/run.sh status

e2e-logs:
	./deploy/e2e/run.sh logs

e2e-down:
	./deploy/e2e/run.sh down

e2e-remote:
	MWAF_E2E_RUNTIME_DIR="$(MWAF_E2E_REMOTE_RUNTIME_DIR)" MWAF_E2E_PROJECT_NAME="$(MWAF_E2E_REMOTE_PROJECT)" ./deploy/e2e/run.sh all --admin-url "$(MWAF_E2E_REMOTE_ADMIN_URL)" --ca-cert "$(MWAF_E2E_REMOTE_CA_CERT)"

e2e-remote-verify:
	MWAF_E2E_RUNTIME_DIR="$(MWAF_E2E_REMOTE_RUNTIME_DIR)" ./deploy/e2e/run.sh verify

e2e-remote-down:
	MWAF_E2E_RUNTIME_DIR="$(MWAF_E2E_REMOTE_RUNTIME_DIR)" ./deploy/e2e/run.sh down
