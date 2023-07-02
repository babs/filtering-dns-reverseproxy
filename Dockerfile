FROM golang:1.19 AS build-stage

WORKDIR /app

COPY go.mod go.sum vendor *.go /app/
COPY vendor /app/vendor

RUN CGO_ENABLED=0 GOOS=linux go build -o /filtering-dns-reverseproxy

###
FROM debian:bookworm-slim AS build-release-stage

WORKDIR /app/

COPY --from=build-stage /filtering-dns-reverseproxy /app/filtering-dns-reverseproxy

USER nobody:nogroup

ENTRYPOINT ["/app/filtering-dns-reverseproxy"]
