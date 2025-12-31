# SBOM Trust Manager - Docker Image
# Sign and verify SBOMs for supply chain security (EO 14028 compliance)

FROM python:3.11-slim

LABEL org.opencontainers.image.title="sbom-trust-manager"
LABEL org.opencontainers.image.description="Cryptographically sign and verify SBOMs for supply chain security"
LABEL org.opencontainers.image.vendor="Big Data Plumbing"

# Install cosign for real signing (optional, falls back to mock if not available)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install cosign (optional - will use mock if not available)
RUN curl -sSL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /usr/local/bin/cosign \
    && chmod +x /usr/local/bin/cosign \
    || echo "Cosign installation failed, will use mock signer"

WORKDIR /app

# Copy project files
COPY pyproject.toml README.md ./
COPY sbom_trust ./sbom_trust

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

ENV PORT=8080
EXPOSE 8080

# Default: run the CLI (can be overridden to run API)
ENTRYPOINT ["sbom-trust"]
CMD ["--help"]

