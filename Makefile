SHELL := /bin/sh

.PHONY: fmt build-manager build-agent dev dev-down dev-db-logs prepare deploy pull prepare-dev deploy-dev pull-dev down logs

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
