# syntax=docker/dockerfile:1
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /out/mongodb-tenant-proxy ./cmd/mongodb-tenant-proxy

RUN mkdir -p /state

# distroless "nonroot" runs as uid/gid 65532; there is no shell, so the
# healthcheck is the binary itself.
FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.title="mongodb-tenant-proxy" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/Netquor/mongodb-tenant-proxy"
COPY --from=build /out/mongodb-tenant-proxy /mongodb-tenant-proxy
# State dir (store.path, audit logs); owned by the runtime user so fresh volumes are writable.
COPY --from=build --chown=65532:65532 /state /var/lib/mongodb-tenant-proxy
USER 65532:65532
EXPOSE 27018 9102 9103
# Probes metricsAddr's /healthz (override with MTP_HEALTH_URL).
HEALTHCHECK --interval=15s --timeout=4s --start-period=10s --retries=3 \
    CMD ["/mongodb-tenant-proxy", "healthcheck", "-config", "/etc/mongodb-tenant-proxy/proxy.json"]
ENTRYPOINT ["/mongodb-tenant-proxy"]
CMD ["serve", "-config", "/etc/mongodb-tenant-proxy/proxy.json"]
