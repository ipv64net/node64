VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= ghcr.io/ipv64net/node64
LDFLAGS := -s -w -X main.Version=$(VERSION)
GOFLAGS := -trimpath

.PHONY: build run test vet tidy docker docker-multiarch clean

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/node64 ./cmd/node64

run: build
	NODE64_DATA_DIR=./data NODE64_LOG_LEVEL=debug ./bin/node64

test:
	go test ./... -count=1

vet:
	go vet ./...

tidy:
	go mod tidy

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

# Multi-Arch-Image (amd64 + arm64). Push mit PUSH=--push
docker-multiarch:
	docker buildx build --platform linux/amd64,linux/arm64 --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest $(PUSH) .

clean:
	rm -rf bin dist

# ---- hub (Serverdienst Healthchecks 2.0)
hub:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.Version=$(VERSION)" -o build/hub-linux-amd64 ./cmd/hub

hub-deploy:
	bash deploy/server/hub-deploy.sh $(VERSION)
