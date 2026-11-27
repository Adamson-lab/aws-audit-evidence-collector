SHELL := /bin/bash
COMPOSE_FILE := deploy/docker-compose.yml

.PHONY: up down run test bench tidy build lint

up:
	docker compose -f $(COMPOSE_FILE) up -d --wait

down:
	docker compose -f $(COMPOSE_FILE) down -v

tidy:
	go mod tidy

build:
	go build -o bin/aws-audit-evidence-collector ./cmd/collector

lint:
	gofmt -l .
	go vet ./...

run:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	EVIDENCE_BUCKET=compliance-audit-evidence \
	OPA_URL=http://localhost:8181 \
	WEBHOOK_HMAC_SECRET=local-dev-audit-secret \
	go run ./cmd/collector

test:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	EVIDENCE_BUCKET=compliance-audit-evidence \
	OPA_URL=http://localhost:8181 \
	WEBHOOK_HMAC_SECRET=local-dev-audit-secret \
	go test -v -race ./...

bench:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	EVIDENCE_BUCKET=compliance-audit-evidence \
	OPA_URL=http://localhost:8181 \
	WEBHOOK_HMAC_SECRET=local-dev-audit-secret \
	go test -bench=. -benchmem ./tests/...
