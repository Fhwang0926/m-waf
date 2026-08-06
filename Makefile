SHELL := /bin/sh

.PHONY: fmt build-manager build-agent dev dev-down dev-db-logs prepare deploy pull prepare-dev deploy-dev pull-dev down logs e2e e2e-up e2e-verify e2e-status e2e-logs e2e-down

fmt:
	gofmt -w cmd internal migrations web/assets.go

build-manager:
	mkdir -p bin
	go build -trimpath -o bin/mwaf-manager ./cmd/mwaf-manager

build-agent:
	mkdir -p bin
	go build -trimpath -o bin/mwaf-agent ./cmd/mwaf-agent

dev:
	sh ./deploy/compose/run-local.sh

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
