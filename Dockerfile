# syntax=docker/dockerfile:1

# ---- Build (reines Go, kein CGO, Cross-Compile ueber TARGETOS/TARGETARCH)
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.Version=$VERSION" -o /out/node64 ./cmd/node64
# Datenverzeichnis mit passenden Rechten fuer den Nicht-Root-Benutzer vorbereiten
RUN mkdir -p /out/data && chown 65532:65532 /out/data
# Ports unter 1024 (DNS64: 53, spaeter 853) und ICMP ohne Root: die Rechte bekommt nur das Binary, und nur als
# "erlaubt" (+p). Node64 schaltet sie beim Start selbst scharf (internal/caps); fehlen sie im Container (cap_drop,
# Podman), startet es trotzdem. Der Prozess laeuft weiter als 65532.
RUN apk add --no-cache libcap && setcap cap_net_bind_service,cap_net_raw=+p /out/node64

# ---- CA-Zertifikate (Zeitzonen sind im Binary eingebettet). Laeuft auf der
#      Build-Plattform, die Zertifikate sind architekturunabhaengig.
FROM --platform=$BUILDPLATFORM alpine:3.22 AS certs
RUN apk add --no-cache ca-certificates

# ---- Laufzeit: leeres Image, nur das Binary
FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/node64 /node64
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV NODE64_DATA_DIR=/data \
    NODE64_HTTP_PORT=8080 \
    NODE64_HTTPS_PORT=0
VOLUME ["/data"]
# 53/udp+tcp nur mit Modul DNS64 (empfohlen: Host-Netzwerk, siehe README)
EXPOSE 8080 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["/node64", "healthcheck"]
ENTRYPOINT ["/node64"]
