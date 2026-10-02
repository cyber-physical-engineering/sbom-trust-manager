"""Command-line tests: the README walkthrough, tampering, and mock handling."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sbom_trust.cli import main as cli

runner = CliRunner()


@pytest.fixture
def signed_example(tmp_path: Path) -> Path:
    sbom = tmp_path / "example-sbom.json"
    result = runner.invoke(cli.app, ["generate-example", "--output", str(sbom)])
    assert result.exit_code == 0
    result = runner.invoke(cli.app, ["sign", str(sbom), "--mock"])
    assert result.exit_code == 0
    return sbom


def test_walkthrough_mock_sign_verify_inspect(signed_example: Path) -> None:
    bundle_path = signed_example.with_suffix(".json.sig.json")
    assert bundle_path.exists()

    result = runner.invoke(cli.app, ["verify", str(signed_example), "--mock"])
    assert result.exit_code == 0
    assert "matches its signature bundle" in result.output

    result = runner.invoke(cli.app, ["inspect", str(bundle_path)])
    assert result.exit_code == 0
    assert "Mock:" in result.output
    assert "TLog" not in result.output


def test_one_changed_byte_fails_verification(signed_example: Path) -> None:
    data = signed_example.read_bytes()
    signed_example.write_bytes(data.replace(b"41.0.0", b"41.0.1", 1))

    result = runner.invoke(cli.app, ["verify", str(signed_example), "--mock"])
    assert result.exit_code == 1


def test_mock_bundle_is_refused_without_mock_flag(signed_example: Path) -> None:
    result = runner.invoke(cli.app, ["verify", str(signed_example)])
    assert result.exit_code == 1


def test_real_bundle_is_refused_in_mock_mode(signed_example: Path) -> None:
    bundle_path = signed_example.with_suffix(".json.sig.json")
    bundle = json.loads(bundle_path.read_text())
    bundle["mock"] = False
    bundle_path.write_text(json.dumps(bundle))

    result = runner.invoke(cli.app, ["verify", str(signed_example), "--mock"])
    assert result.exit_code == 1


def test_sign_fails_when_cosign_is_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_check_cosign_available", lambda: False)
    sbom = tmp_path / "example-sbom.json"
    runner.invoke(cli.app, ["generate-example", "--output", str(sbom)])

    result = runner.invoke(cli.app, ["sign", str(sbom)])
    assert result.exit_code == 1
    assert not sbom.with_suffix(".json.sig.json").exists()


def test_no_keyless_needs_a_key(tmp_path: Path) -> None:
    sbom = tmp_path / "example-sbom.json"
    runner.invoke(cli.app, ["generate-example", "--output", str(sbom)])

    result = runner.invoke(cli.app, ["sign", str(sbom), "--no-keyless"])
    assert result.exit_code != 0
