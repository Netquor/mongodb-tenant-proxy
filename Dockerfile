FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mongodb-tenant-proxy ./cmd/mongodb-tenant-proxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mongodb-tenant-proxy /mongodb-tenant-proxy
EXPOSE 27018
ENTRYPOINT ["/mongodb-tenant-proxy"]
CMD ["serve", "-config", "/etc/mongodb-tenant-proxy/proxy.json"]
