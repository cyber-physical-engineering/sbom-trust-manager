# SBOM Trust Manager

**Prevent supply chain attacks. Cryptographically sign and verify your software bill of materials.**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](pyproject.toml)
[![Docker](https://img.shields.io/badge/docker-ready-green.svg)](Dockerfile)

## The Problem

The US Government (Executive Order 14028) now **mandates** a Software Bill of Materials (SBOM) for software it buys. Medical device manufacturers must track every component. But generating an SBOM is only half the battle — you need to **prove** its integrity.

## The Solution

SBOM Trust Manager provides:
1. **Signing**: Cryptographically sign SBOMs using Sigstore (cosign) or local keys
2. **Verification**: Verify SBOM authenticity and integrity
3. **Tamper Detection**: Detect if any byte of the SBOM has been modified

```
┌──────────────┐     ┌────────────────┐     ┌─────────────────┐
│  Your Code   │ ──▶ │  sbom-trust    │ ──▶ │  Signed SBOM    │
│  + Deps      │     │  sign          │     │  + Bundle       │
└──────────────┘     └────────────────┘     └─────────────────┘
```

## Features

- 📦 **Format Agnostic**: Signs SPDX, CycloneDX, or any file format
- 🔐 **Sigstore Integration**: Uses `cosign` for keyless signing (OIDC)
- 🔑 **Local Keys**: Supports local key signing for offline environments
- 🧪 **Mock Mode**: Built-in mock signer for testing/dev without external tools
- 🐳 **Docker Ready**: Includes `cosign` installation (optional)

## Quick Start

### CLI Usage

```bash
# Install
pip install -e .

# Generate an example SBOM (CycloneDX)
sbom-trust generate-example --output app.sbom.json

# Sign with Mock signer (good for testing)
sbom-trust sign app.sbom.json --mock --output app.sbom.sig.json

# Verify the signature
sbom-trust verify app.sbom.json --signature app.sbom.sig.json --mock

# Inspect signature details
sbom-trust inspect app.sbom.sig.json
```

### Production Signing (with Cosign)

Prerequisite: Install [cosign](https://docs.sigstore.dev/cosign/installation/)

```bash
# Sign using Sigstore (opens browser for OIDC login)
sbom-trust sign app.sbom.json

# Verify using Sigstore
sbom-trust verify app.sbom.json
```

### Docker Usage

The Docker image attempts to install `cosign`. If unavailable, it falls back to mock mode.

```bash
# Build
docker build -t sbom-trust .

# Sign an SBOM
docker run --rm -v $(pwd):/data sbom-trust \
  sign /data/app.sbom.json --mock --output /data/app.sbom.sig.json
```

## Compliance Mappings

| Requirement | Source | How SBOM Trust Manager Helps |
|-------------|--------|------------------------------|
| SBOM Integrity | EO 14028 | ✅ Cryptographic signatures |
| Provenance | SLSA | ✅ Signature bundles |
| Component Tracking | 21 CFR 820.30 | ✅ Verifiable artifacts |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/
```

## Related Projects

- [fhir-verifiable-credentials](../fhir-verifiable-credentials) - FHIR to VC conversion
- [compliance-evidence-locker](../compliance-evidence-locker) - Automated audit evidence

## License

Apache 2.0 - See [LICENSE](LICENSE)
