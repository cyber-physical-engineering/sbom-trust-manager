# SBOM Trust Manager

A Python command-line tool that hashes a software bill of materials (SBOM), writes a signature bundle, and checks a file against its bundle. Real signing needs the `cosign` binary. A mock mode shows the bundle format and the hash check without a key.

**Status: prototype.** 13 tests pass, and `ruff check .` and `mypy sbom_trust` (strict) are clean (October 2, 2026; Python 3.9.6, Apple Silicon Mac). The walkthrough below runs as written. The cosign path was not run.

James Thornton set the architecture and requirements. The code was written with AI-assisted development in late 2025. The tests and checks were re-run in October 2026.

## What it does

Four commands: `sign`, `verify`, `inspect` and `generate-example`.

- `sign` takes the SHA-256 of the whole file and writes a JSON bundle: `sbom_hash`, `signature`, `certificate`, `transparency_log_entry`, `signed_at` and `mock`.
- `sign --mock` writes a placeholder signature with no key and marks the bundle `"mock": true`. It exists to show the format.
- With cosign installed, `sign` calls `cosign sign-blob`, keyless by default or with `--no-keyless --key <file>` for a local key. Without cosign, `sign` and `verify` exit 1 unless `--mock` is given.
- `verify` recomputes the file's SHA-256 and compares it with the bundle. A one-byte change fails. It refuses a mock bundle without `--mock`, and a real bundle with `--mock`.
- `inspect` prints the bundle's fields and says "Mock: yes" for a mock bundle.
- `generate-example` writes a small CycloneDX 1.5 SBOM that validates against the official 1.5 schema.
- The tool works on any file. It does not parse or validate the SBOM.

## Quick start

```bash
pip install -e .

sbom-trust generate-example --output app.sbom.json
sbom-trust sign app.sbom.json --mock --output app.sbom.sig.json
sbom-trust verify app.sbom.json --signature app.sbom.sig.json --mock
sbom-trust inspect app.sbom.sig.json
```

All four ran in a clean virtual environment on October 2, 2026. Change one byte of `app.sbom.json` and `verify` reports a hash mismatch and exits 1.

Run the tests:

```bash
pip install -e ".[dev]"
pytest
```

## Signing with cosign

Install cosign from https://docs.sigstore.dev/cosign/system_config/installation/. Then:

```bash
sbom-trust sign app.sbom.json                        # keyless; opens a browser for the OIDC login
sbom-trust sign app.sbom.json --no-keyless --key cosign.key
sbom-trust verify app.sbom.json
```

This path was not run in the October 2026 checks, and it has two known gaps. `verify` passes no `--certificate-identity` or `--certificate-oidc-issuer` flag, which current cosign requires for keyless verification, so keyless verification is not expected to pass as coded. There is no verify path for a bundle signed with a local key.

## Where SBOMs are required

For cyber devices, FD&C Act section 524B(b)(3) requires an SBOM in the premarket submission, and FDA's premarket cybersecurity guidance (February 3, 2026) says so plainly. Executive Order 14028 (2021) named SBOMs among recommended software supply-chain practices. OMB M-26-05 (January 2026) rescinded memoranda M-22-18 and M-23-16, and it leaves a federal SBOM as a contract option an agency may choose. Neither rule asks for a signed SBOM. Signing one adds an integrity check that this prototype explores.

## Limits

- Mock mode has no key. Anyone can make a mock bundle that verifies, so it catches accidental edits only.
- The hash covers the file, not the bundle. `signed_at`, `certificate` and `transparency_log_entry` can be changed freely.
- The cosign path is untested here. Keyless verification passes no identity flags, key-signed bundles have no verify path, and the `sign-blob` flags may be stale against cosign v3.
- Nothing here enforces policy or generates keys.
- The Dockerfile fetches cosign for linux-amd64 only, and it was not built in October 2026.
- The tests cover the mock path and the command line. The cosign backend is untested.

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
