"""Tests for the SBOM Trust Manager."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from sbom_trust.core.sbom_signer import (
    MockSignerBackend,
    SBOMSigner,
    SignatureBundle,
)


def _create_example_sbom(path: Path) -> None:
    """Create an example SBOM for testing."""
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {"type": "library", "name": "test-lib", "version": "1.0.0"},
        ],
    }
    path.write_text(json.dumps(sbom))


def test_mock_signer_signs_sbom():
    """Test that MockSignerBackend produces a signature."""
    backend = MockSignerBackend(signer_id="test@example.com")
    signer = SBOMSigner(backend)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
        _create_example_sbom(path)

    try:
        bundle = signer.sign(path)

        assert bundle.sbom_hash is not None
        assert len(bundle.sbom_hash) == 64  # SHA-256 hex
        assert bundle.signature is not None
        assert bundle.signed_at is not None
    finally:
        path.unlink(missing_ok=True)


def test_mock_signer_verification_succeeds():
    """Test that valid signatures verify correctly."""
    backend = MockSignerBackend()
    signer = SBOMSigner(backend)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
        _create_example_sbom(path)

    try:
        bundle = signer.sign(path)
        is_valid = signer.verify(path, bundle)

        assert is_valid is True
    finally:
        path.unlink(missing_ok=True)


def test_mock_signer_detects_tampered_file():
    """Test that tampered files fail verification."""
    backend = MockSignerBackend()
    signer = SBOMSigner(backend)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
        _create_example_sbom(path)

    try:
        bundle = signer.sign(path)

        # Tamper with the file
        original = path.read_text()
        path.write_text(original.replace("test-lib", "evil-lib"))

        # Should raise ValueError due to hash mismatch
        try:
            signer.verify(path, bundle)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "hash mismatch" in str(e).lower()
    finally:
        path.unlink(missing_ok=True)


def test_signature_bundle_serialization():
    """Test SignatureBundle to/from dict."""
    bundle = SignatureBundle(
        sbom_hash="abc123" * 10 + "abcd",
        signature="sig123",
        certificate="cert456",
        transparency_log_entry="tlog entry",
        signed_at="2025-01-01T00:00:00Z",
    )

    data = bundle.to_dict()
    restored = SignatureBundle.from_dict(data)

    assert restored.sbom_hash == bundle.sbom_hash
    assert restored.signature == bundle.signature
    assert restored.certificate == bundle.certificate
    assert restored.transparency_log_entry == bundle.transparency_log_entry
    assert restored.signed_at == bundle.signed_at


def test_signature_bundle_json_roundtrip():
    """Test SignatureBundle JSON serialization."""
    bundle = SignatureBundle(
        sbom_hash="hash123",
        signature="sig123",
        certificate=None,
        transparency_log_entry=None,
        signed_at="2025-01-01T00:00:00Z",
    )

    json_str = bundle.to_json()
    data = json.loads(json_str)
    restored = SignatureBundle.from_dict(data)

    assert restored.sbom_hash == bundle.sbom_hash
    assert restored.certificate is None


def test_deterministic_mock_signatures():
    """Test that mock signatures are deterministic for the same content."""
    backend = MockSignerBackend(signer_id="test@example.com")

    data1 = b'{"test": "data"}'
    data2 = b'{"test": "data"}'
    data3 = b'{"test": "different"}'

    sig1, _, _ = backend.sign(data1)
    sig2, _, _ = backend.sign(data2)
    sig3, _, _ = backend.sign(data3)

    assert sig1 == sig2  # Same content = same signature
    assert sig1 != sig3  # Different content = different signature


def test_mock_signer_includes_tlog_entry():
    """Test that mock signer includes a transparency log entry."""
    backend = MockSignerBackend()
    _, _, tlog = backend.sign(b"test data")

    assert tlog is not None
    assert "tlog" in tlog.lower()

