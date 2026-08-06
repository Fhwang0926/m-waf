SHELL := /bin/sh

.PHONY: fmt build-manager build-agent prepare-dev deploy-dev pull-dev down logs

fmt:
	gofmt -w cmd internal migrations web/assets.go

build-manager:
	mkdir -p bin
	go build -trimpath -o bin/mwaf-manager ./cmd/mwaf-manager

build-agent:
	mkdir -p bin
	go build -trimpath -o bin/mwaf-agent ./cmd/mwaf-agent

prepare-dev:
	./deploy/compose/prepare.sh

pull-dev: prepare-dev
	docker compose --env-file deploy/compose/.env -f deploy/compose/compose.yaml pull

deploy-dev: prepare-dev
	docker compose --env-file deploy/compose/.env -f deploy/compose/compose.yaml up -d

down:
	docker compose --env-file deploy/compose/.env -f deploy/compose/compose.yaml down

logs:
	docker compose --env-file deploy/compose/.env -f deploy/compose/compose.yaml logs -f --tail=200
