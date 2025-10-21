# Copyright 2025 Alejandro Martínez Corriá and the Thinkube contributors
# SPDX-License-Identifier: Apache-2.0

# Multi-stage build for minimal image size
FROM library/rust:alpine AS builder

# Install build dependencies
# - musl-dev: Required for musl libc development files
# - pkgconfig: For finding system libraries
# - openssl-dev openssl-libs-static: OpenSSL headers and static libraries for linking
# - git: For cargo to fetch git dependencies
# - build-base: Complete build toolchain (gcc, make, etc.)
RUN apk add --no-cache \
    musl-dev \
    pkgconfig \
    openssl-dev \
    openssl-libs-static \
    git \
    build-base

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Build dependencies (this is cached if Cargo.toml doesn't change)
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -rf src

# Copy source code
COPY src ./src

# Build application
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM library/alpine:3.20

# Install runtime dependencies and external tools
RUN apk add --no-cache \
    ca-certificates \
    python3 \
    py3-pip \
    nodejs \
    npm \
    git \
    curl \
    wget \
    jq

# Install Python package management tools
RUN pip3 install --no-cache-dir --break-system-packages uv

# Install JavaScript package management tools
RUN npm install -g pnpm

# Install security scanning tools
RUN wget -q https://github.com/google/osv-scanner/releases/download/v2.2.2/osv-scanner_linux_amd64 -O /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# Create non-root user
RUN addgroup -g 1000 appuser && \
    adduser -D -s /bin/sh -u 1000 -G appuser appuser

# Copy binary from builder
COPY --from=builder /app/target/release/tk-package-version /usr/local/bin/tk-package-version

# Change ownership
RUN chown appuser:appuser /usr/local/bin/tk-package-version

# Create temp directory for tool operations
RUN mkdir -p /tmp/tk-package-version && \
    chown -R appuser:appuser /tmp/tk-package-version

USER appuser

# Set working directory
WORKDIR /tmp/tk-package-version

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:18080/health || exit 1

# Expose port
EXPOSE 18080

# Set environment variables
ENV PORT=18080 \
    BASE_URL=https://control.thinkube.com/tk-package-version \
    LOG_LEVEL=info \
    CACHE_TTL=300

# Run the binary
ENTRYPOINT ["tk-package-version"]