# syntax=docker/dockerfile:1

# Stage 1: Build the static Go binary
FROM golang:alpine AS builder

WORKDIR /src

# Install certificates and git
RUN apk add --no-cache ca-certificates git tzdata

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and embedded assets
COPY . .

# Build statically linked binary with stripped symbols
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/ssh_buttons .

# Stage 2: Minimal runtime image
FROM alpine:3.21

WORKDIR /app

# Install runtime dependencies: ca-certificates for TLS and tzdata for timezones
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S appgroup -g 10001 \
    && adduser -S appuser -u 10001 -G appgroup \
    && mkdir -p /app/keys \
    && chown -R appuser:appgroup /app

# Copy binary from builder
COPY --from=builder /bin/ssh_buttons /app/ssh_buttons

# Use non-root user for security
USER appuser:appgroup

# Expose default HTTP port
EXPOSE 8080

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/app/ssh_buttons"]
CMD ["-config", "/app/config.yml"]
