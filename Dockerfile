ARG VERSION=dev

FROM golang:1.26-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION}" -o /authentik-operator ./cmd/authentik-operator

FROM alpine:3
RUN apk add --no-cache ca-certificates

COPY --from=builder /authentik-operator /app/authentik-operator

USER 65532:65532
ENTRYPOINT ["/app/authentik-operator"]
