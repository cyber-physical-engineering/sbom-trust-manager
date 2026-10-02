# SBOM Trust Manager: Docker image
# Hashes and signs SBOM files. cosign is installed for real signing; the image was not built in the October 2026 checks.

FROM python:3.11-slim

LABEL org.opencontainers.image.title="sbom-trust-manager"
LABEL org.opencontainers.image.description="Hash an SBOM file and write or check a signature bundle (prototype)"

# curl, to fetch cosign
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install cosign (linux-amd64 only). Without it, sign and verify need --mock.
RUN curl -sSL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /usr/local/bin/cosign \
    && chmod +x /usr/local/bin/cosign \
    || echo "cosign download failed; sign and verify will need --mock"

WORKDIR /app

# Copy project files
COPY pyproject.toml README.md ./
COPY sbom_trust ./sbom_trust

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

ENTRYPOINT ["sbom-trust"]
CMD ["--help"]

