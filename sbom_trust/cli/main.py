"""SBOM Trust Manager CLI.

Commands for signing and verifying Software Bills of Materials.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Optional

import typer

from ..core.sbom_signer import (
    CosignBackend,
    MockSignerBackend,
    SBOMSigner,
    SignatureBundle,
    SignerBackend,
)

app = typer.Typer(
    add_completion=False,
    help="Hash an SBOM file and write or check a signature bundle",
)


COSIGN_INSTALL_URL = "https://docs.sigstore.dev/cosign/system_config/installation/"


def _check_cosign_available() -> bool:
    """Check if cosign is available in PATH."""
    return shutil.which("cosign") is not None


@app.command()
def sign(
    sbom_path: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="Path to the SBOM file (any file; it is hashed, not parsed)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path for signature bundle (default: <sbom>.sig.json)",
    ),
    keyless: bool = typer.Option(
        True,
        "--keyless/--no-keyless",
        help="Keyless signing through cosign (opens an OIDC login)",
    ),
    key: Optional[Path] = typer.Option(
        None,
        "--key",
        "-k",
        exists=True,
        help="Path to a private key for cosign (with --no-keyless)",
    ),
    mock: bool = typer.Option(
        False,
        "--mock",
        help="Mock mode: no key, shows the bundle format (for tests)",
    ),
) -> None:
    """Hash an SBOM file and write a signature bundle."""
    # Determine output path
    if output is None:
        output = sbom_path.with_suffix(sbom_path.suffix + ".sig.json")

    # Select backend
    backend: SignerBackend
    if mock:
        backend = MockSignerBackend(signer_id="local-test@example.com")
        typer.echo("⚠ Mock mode: no key is used, and the bundle proves nothing about who signed it")
    else:
        if not keyless and key is None:
            raise typer.BadParameter("--no-keyless needs --key")
        if not _check_cosign_available():
            typer.echo(
                "✗ cosign not found. Install it, or pass --mock to test without signing.",
                err=True,
            )
            typer.echo(f"  Install cosign: {COSIGN_INSTALL_URL}", err=True)
            raise typer.Exit(1)
        try:
            backend = CosignBackend(use_keyless=keyless, key_path=key)
        except ValueError as e:
            raise typer.BadParameter(str(e)) from e

    # Sign
    signer = SBOMSigner(backend)
    bundle = signer.sign(sbom_path)

    # Write bundle
    output.write_text(bundle.to_json())

    typer.echo(f"✓ SBOM signed: {sbom_path}")
    typer.echo(f"  Hash:      {bundle.sbom_hash[:16]}...")
    typer.echo(f"  Signature: {output}")
    if bundle.transparency_log_entry:
        typer.echo(f"  TLog:      {bundle.transparency_log_entry}")


@app.command()
def verify(
    sbom_path: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="Path to the SBOM file (any file; it is hashed, not parsed)",
    ),
    signature: Optional[Path] = typer.Option(
        None,
        "--signature",
        "-s",
        exists=True,
        help="Path to signature bundle (default: <sbom>.sig.json)",
    ),
    mock: bool = typer.Option(
        False,
        "--mock",
        help="Mock mode: check a bundle made with sign --mock",
    ),
) -> None:
    """Check an SBOM file against its signature bundle."""
    # Find signature file
    if signature is None:
        signature = sbom_path.with_suffix(sbom_path.suffix + ".sig.json")
        if not signature.exists():
            raise typer.BadParameter(
                f"Signature file not found: {signature}. Use --signature to specify."
            )

    # Load bundle
    try:
        bundle_data = json.loads(signature.read_text())
        bundle = SignatureBundle.from_dict(bundle_data)
    except (json.JSONDecodeError, KeyError) as e:
        raise typer.BadParameter(f"Invalid signature bundle: {e}") from e

    # A mock bundle is only checked in mock mode, and a real one never is.
    if bundle.mock and not mock:
        typer.echo("✗ This bundle came from the mock signer. Pass --mock to check it.", err=True)
        raise typer.Exit(1)
    if mock and not bundle.mock:
        typer.echo(
            "✗ This bundle was not made by the mock signer. Drop --mock to verify it.",
            err=True,
        )
        raise typer.Exit(1)

    # Select backend
    backend: SignerBackend
    if mock:
        backend = MockSignerBackend()
    elif not _check_cosign_available():
        typer.echo("✗ cosign not found. Install it to verify a cosign signature.", err=True)
        typer.echo(f"  Install cosign: {COSIGN_INSTALL_URL}", err=True)
        raise typer.Exit(1)
    else:
        backend = CosignBackend(use_keyless=True)

    # Verify
    signer = SBOMSigner(backend)

    try:
        is_valid = signer.verify(sbom_path, bundle)
    except ValueError as e:
        typer.echo(f"✗ Verification failed: {e}", err=True)
        raise typer.Exit(1) from e

    if is_valid:
        typer.echo(f"✓ {sbom_path} matches its signature bundle")
        typer.echo(f"  Signed at: {bundle.signed_at}")
    else:
        typer.echo("✗ The signature does not verify", err=True)
        raise typer.Exit(1)


@app.command()
def inspect(
    signature: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to signature bundle"
    ),
) -> None:
    """Print the fields of a signature bundle."""
    try:
        bundle_data = json.loads(signature.read_text())
        bundle = SignatureBundle.from_dict(bundle_data)
    except (json.JSONDecodeError, KeyError) as e:
        raise typer.BadParameter(f"Invalid signature bundle: {e}") from e

    typer.echo(f"Signature Bundle: {signature}")
    typer.echo(f"  SBOM Hash:  {bundle.sbom_hash}")
    typer.echo(f"  Signed At:  {bundle.signed_at}")
    typer.echo(f"  Signature:  {bundle.signature[:40]}...")

    if bundle.certificate:
        typer.echo(f"  Certificate: {bundle.certificate[:40]}...")
    else:
        typer.echo("  Certificate: none (signed with a local key)")

    if bundle.transparency_log_entry:
        typer.echo(f"  TLog Entry: {bundle.transparency_log_entry}")
    if bundle.mock:
        typer.echo("  Mock:       yes (made by the mock signer; not a real signature)")


@app.command()
def generate_example(
    output: Path = typer.Option(
        Path("example-sbom.json"),
        "--output",
        "-o",
        help="Output path for the example SBOM",
    ),
) -> None:
    """Write a small CycloneDX 1.5 example SBOM."""
    example_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version": 1,
        "metadata": {
            "timestamp": "2025-01-01T00:00:00Z",
            "tools": {
                "components": [
                    {"type": "application", "name": "sbom-trust-manager", "version": "0.1.0"}
                ]
            },
            "component": {
                "type": "application",
                "name": "example-app",
                "version": "1.0.0",
            },
        },
        "components": [
            {
                "type": "library",
                "name": "cryptography",
                "version": "41.0.0",
                "purl": "pkg:pypi/cryptography@41.0.0",
            },
            {
                "type": "library",
                "name": "pydantic",
                "version": "2.0.0",
                "purl": "pkg:pypi/pydantic@2.0.0",
            },
        ],
    }

    output.write_text(json.dumps(example_sbom, indent=2))
    typer.echo(f"✓ Generated example SBOM: {output}")


if __name__ == "__main__":
    app()

