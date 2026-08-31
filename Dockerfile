# Build stage
FROM gcc:13 AS builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    make \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY src/ ./src/
COPY config.ini ./
COPY Makefile ./

# Build
RUN make

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libsqlite3-0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create data directory
RUN mkdir -p data

# Copy built binary and config
COPY --from=builder /app/property_manage ./
COPY --from=builder /app/config.ini ./

# Create non-root user
RUN useradd -r -s /bin/false appuser && \
    chown -R appuser:appuser /app
USER appuser

# Expose no ports (CLI application)

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ./property_manage --version || exit 1

# Entry point
ENTRYPOINT ["./property_manage"]