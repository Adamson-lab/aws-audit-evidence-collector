FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/aws-audit-evidence-collector ./cmd/collector

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl
COPY --from=builder /out/aws-audit-evidence-collector /usr/local/bin/aws-audit-evidence-collector
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/aws-audit-evidence-collector"]
