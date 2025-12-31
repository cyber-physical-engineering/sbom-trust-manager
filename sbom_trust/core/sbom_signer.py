"""SBOM Signing and Verification with Sigstore/cosign.

This module provides cryptographic signing of Software Bills of Materials (SBOM)
for supply chain security compliance (EO 14028).
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class SignatureBundle:
    """Container for SBOM signature and metadata."""

    sbom_hash: str
    signature: str
    certificate: Optional[str]
    transparency_log_entry: Optional[str]
    signed_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sbom_hash": self.sbom_hash,
            "signature": self.signature,
            "certificate": self.certificate,
            "transparency_log_entry": self.transparency_log_entry,
            "signed_at": self.signed_at,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SignatureBundle":
        return cls(
            sbom_hash=data["sbom_hash"],
            signature=data["signature"],
            certificate=data.get("certificate"),
            transparency_log_entry=data.get("transparency_log_entry"),
            signed_at=data.get("signed_at", ""),
        )


class SignerBackend(ABC):
    """Abstract base class for signing backends."""

    @abstractmethod
    def sign(self, data: bytes) -> tuple[str, Optional[str], Optional[str]]:
        """Sign data and return (signature, certificate, tlog_entry)."""
        pass

    @abstractmethod
    def verify(
        self,
        data: bytes,
        signature: str,
        certificate: Optional[str],
    ) -> bool:
        """Verify a signature."""
        pass


class MockSignerBackend(SignerBackend):
    """Mock signer for testing without cosign installed."""

    def __init__(self, signer_id: str = "test-signer@example.com"):
        self.signer_id = signer_id

    def sign(self, data: bytes) -> tuple[str, Optional[str], Optional[str]]:
        """Create a mock signature."""
        # Create deterministic "signature" based on data hash
        data_hash = hashlib.sha256(data).hexdigest()
        mock_sig = base64.b64encode(
            f"MOCK_SIG:{data_hash}:{self.signer_id}".encode()
        ).decode()

        mock_cert = base64.b64encode(
            f"MOCK_CERT:{self.signer_id}".encode()
        ).decode()

        mock_tlog = "tlog entry created with index: 12345678"

        return mock_sig, mock_cert, mock_tlog

    def verify(
        self,
        data: bytes,
        signature: str,
        certificate: Optional[str],
    ) -> bool:
        """Verify mock signature."""
        try:
            decoded = base64.b64decode(signature).decode()
            if not decoded.startswith("MOCK_SIG:"):
                return False

            parts = decoded.split(":")
            if len(parts) != 3:
                return False

            expected_hash = parts[1]
            actual_hash = hashlib.sha256(data).hexdigest()

            return expected_hash == actual_hash
        except Exception:
            return False


class CosignBackend(SignerBackend):
    """Cosign-based signer using Sigstore."""

    def __init__(
        self,
        use_keyless: bool = True,
        key_path: Optional[Path] = None,
    ):
        self.use_keyless = use_keyless
        self.key_path = key_path

        if not use_keyless and not key_path:
            raise ValueError("Must provide key_path if not using keyless signing")

    def sign(self, data: bytes) -> tuple[str, Optional[str], Optional[str]]:
        """Sign using cosign."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(data)
            data_path = f.name

        with tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as sig_file:
            sig_path = sig_file.name

        with tempfile.NamedTemporaryFile(suffix=".cert", delete=False) as cert_file:
            cert_path = cert_file.name

        try:
            if self.use_keyless:
                cmd = [
                    "cosign", "sign-blob",
                    "--yes",
                    "--output-signature", sig_path,
                    "--output-certificate", cert_path,
                    data_path,
                ]
            else:
                cmd = [
                    "cosign", "sign-blob",
                    "--key", str(self.key_path),
                    "--output-signature", sig_path,
                    "--tlog-upload=false",
                    data_path,
                ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                raise RuntimeError(f"Cosign signing failed: {result.stderr}")

            with open(sig_path) as f:
                signature = f.read().strip()

            certificate = None
            if self.use_keyless and Path(cert_path).exists():
                with open(cert_path) as f:
                    certificate = f.read().strip()

            # Extract transparency log entry from stderr
            tlog_entry = None
            for line in result.stderr.split("\n"):
                if "tlog entry created" in line.lower():
                    tlog_entry = line.strip()
                    break

            return signature, certificate, tlog_entry

        finally:
            Path(data_path).unlink(missing_ok=True)
            Path(sig_path).unlink(missing_ok=True)
            Path(cert_path).unlink(missing_ok=True)

    def verify(
        self,
        data: bytes,
        signature: str,
        certificate: Optional[str],
    ) -> bool:
        """Verify using cosign."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(data)
            data_path = f.name

        with tempfile.NamedTemporaryFile(suffix=".sig", delete=False, mode="w") as f:
            f.write(signature)
            sig_path = f.name

        cert_path = None
        if certificate:
            with tempfile.NamedTemporaryFile(
                suffix=".cert", delete=False, mode="w"
            ) as f:
                f.write(certificate)
                cert_path = f.name

        try:
            cmd = ["cosign", "verify-blob", "--signature", sig_path]

            if cert_path:
                cmd.extend(["--certificate", cert_path])

            cmd.append(data_path)

            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0

        finally:
            Path(data_path).unlink(missing_ok=True)
            Path(sig_path).unlink(missing_ok=True)
            if cert_path:
                Path(cert_path).unlink(missing_ok=True)


class SBOMSigner:
    """High-level SBOM signing interface."""

    def __init__(self, backend: Optional[SignerBackend] = None):
        """Initialize with a signer backend.

        Args:
            backend: Signer backend to use. Defaults to MockSignerBackend.
        """
        self.backend = backend or MockSignerBackend()

    def sign(self, sbom_path: Path) -> SignatureBundle:
        """Sign an SBOM file.

        Args:
            sbom_path: Path to SBOM file (SPDX or CycloneDX JSON/XML)

        Returns:
            SignatureBundle with signature and metadata
        """
        sbom_data = Path(sbom_path).read_bytes()
        sbom_hash = hashlib.sha256(sbom_data).hexdigest()

        signature, certificate, tlog_entry = self.backend.sign(sbom_data)

        return SignatureBundle(
            sbom_hash=sbom_hash,
            signature=signature,
            certificate=certificate,
            transparency_log_entry=tlog_entry,
            signed_at=datetime.now(timezone.utc).isoformat(),
        )

    def verify(
        self,
        sbom_path: Path,
        bundle: SignatureBundle,
    ) -> bool:
        """Verify an SBOM signature.

        Args:
            sbom_path: Path to SBOM file
            bundle: Signature bundle from signing

        Returns:
            True if verification succeeds
        """
        sbom_data = Path(sbom_path).read_bytes()
        current_hash = hashlib.sha256(sbom_data).hexdigest()

        # Check hash first
        if current_hash != bundle.sbom_hash:
            raise ValueError("SBOM hash mismatch - file has been modified")

        return self.backend.verify(sbom_data, bundle.signature, bundle.certificate)


class SBOMVerifier:
    """Verify SBOM signatures (alias for backwards compatibility)."""

    def __init__(self, backend: Optional[SignerBackend] = None):
        self._signer = SBOMSigner(backend)

    def verify(
        self,
        sbom_path: Path,
        signature_bundle: SignatureBundle,
        certificate_identity: Optional[str] = None,
        certificate_oidc_issuer: Optional[str] = None,
    ) -> bool:
        """Verify an SBOM signature."""
        # Note: certificate_identity and certificate_oidc_issuer are for
        # Sigstore keyless verification - not implemented in mock
        return self._signer.verify(sbom_path, signature_bundle)
