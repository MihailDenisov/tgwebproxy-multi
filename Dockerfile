FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tgwebproxy ./cmd/tgwebproxy

FROM alpine:3.20
RUN apk add --no-cache ca-certificates libcap && adduser -D -H -u 10001 relay
COPY --from=build /out/tgwebproxy /usr/local/bin/tgwebproxy
# The relay listens on 80 and 443, so an unprivileged user needs the bind
# capability on the binary itself; Docker will not grant it to the process.
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/tgwebproxy
# The certificate cache must outlive the container, or every restart asks
# Let's Encrypt for a fresh certificate and walks into its rate limit.
VOLUME /certs
USER relay
EXPOSE 80 443
ENV TGWP_CERT_DIR=/certs
ENTRYPOINT ["/usr/local/bin/tgwebproxy"]
