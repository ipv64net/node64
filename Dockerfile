# syntax=docker/dockerfile:1

# ---- Build (reines Go, kein CGO, Cross-Compile ueber TARGETOS/TARGETARCH; arm/v7 ueber TARGETVARIANT -> GOARM=7)
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev
# zusaetzliche oeffentliche Schluessel fuers Selbst-Update (nur Tests; der echte steht in internal/selfupdate/keys.go)
ARG UPDATE_KEYS=
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
# GOARM nur fuer arm setzen (arm64 meldet teils die Variante v8, die GOARM nicht kennt)
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    if [ "$TARGETARCH" = "arm" ] && [ -n "$TARGETVARIANT" ]; then export GOARM="${TARGETVARIANT#v}"; fi && \
    KEYS=""; if [ -n "$UPDATE_KEYS" ]; then KEYS="-X github.com/ipv64net/node64/internal/selfupdate.PublicKeys=$UPDATE_KEYS"; fi && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.Version=$VERSION $KEYS" -o /out/node64 ./cmd/node64
# Datenverzeichnis mit passenden Rechten fuer den Nicht-Root-Benutzer vorbereiten
RUN mkdir -p /out/data && chown 65532:65532 /out/data
# Ports unter 1024 (DNS64: 53, spaeter 853) und ICMP ohne Root: die Rechte bekommt nur das Binary, und nur als
# "erlaubt" (+p). Node64 schaltet sie beim Start selbst scharf (internal/caps); fehlen sie im Container (cap_drop,
# Podman), startet es trotzdem. Der Prozess laeuft weiter als 65532. cap_net_admin nur fuer den Firewall-Helfer
# (NODE64_FIREWALL=nftables): wirkt nur, wenn der Container --cap-add NET_ADMIN bekommt.
RUN apk add --no-cache libcap && setcap cap_net_bind_service,cap_net_raw,cap_net_admin=+p /out/node64

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
# Weboberflaeche; dazu nur mit Modul DNS64: DNS 53 (UDP/TCP), DoH 443/TCP, DoT 853/TCP, DoQ 853/UDP
# (empfohlen: Host-Netzwerk, siehe README). Modus ohne Oberflaeche (NODE64_MODE=honeypot): Fallen-Ports je Profil,
# Info-Seite 9064, siehe docs/HONEYPOT64.md
EXPOSE 8080 8443 53/udp 53/tcp 443/tcp 853/tcp 853/udp
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["/node64", "healthcheck"]
ENTRYPOINT ["/node64"]
