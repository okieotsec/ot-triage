# Releasing

How a release of OT Triage is made, so that anyone can check what was published.

## Steps

1. **Prepare:** a pull request bumps `version.py`, regenerates the SBOM (`python3 tools/make_sbom.py`, which needs `pip install cyclonedx-bom`) and dates the changelog's "Unreleased" section. All CI checks must pass before it is merged.
2. **Tag:** an annotated tag `v<version>` on the merge commit, made under the project's own identity.
3. **Build the bundle:** pushing the tag starts the *Release bundle* workflow, which builds `dist/ot-triage-<version>.zip` and its `.sha256` file with `python3 tools/make_bundle.py`, records a signed build-provenance attestation for the zip, and keeps the files as a workflow artifact for 30 days. It does not create the release. To build locally instead, run the same command from a clean checkout of the tag.
4. **Check, then publish:** download the workflow artifact, run `gh attestation verify ot-triage-<version>.zip --repo okieotsec/ot-triage`, and confirm that the checksum matches a local rebuild from the tag. Then make the GitHub release for the tag with the notes from the changelog and three files attached: the bundle, its `.sha256` file, and the SBOM (`ot-triage-<version>.cdx.json`).

## What the bundle contains

Only what is needed to run the application: the Python modules the two entry points import (found by following their imports, so a new module cannot be forgotten), `OT Triage.pyw` (the double-click launcher), `README.md`, `CHANGELOG.md`, `LICENSE`, `SECURITY.md`, `THIRD_PARTY_NOTICES.md`, `docs/`, `sbom/`, the `sample_*.csv` files and a short `START-HERE.txt`. It contains no tests, no tools, no security reports and nothing that git does not track.

## Checking a download

```
sha256sum -c ot-triage-<version>.zip.sha256          # on Windows: certutil -hashfile ot-triage-<version>.zip SHA256
```

To confirm the bundle is what the tag says, check out the tag and run `python3 tools/make_bundle.py`: the build fixes the dates, the order and the permissions, so the checksum matches the one published (for 0.9.0 it matched between GitHub's runner and a developer's Linux machine; zip compression can differ between Python versions, so a very different environment may give different bytes). Build on Linux or macOS to compare with a published bundle; Windows does not record the executable permission, so its zip differs in that one detail.

## Build provenance

The attestation is a signed statement, recorded by GitHub, that names the zip's SHA-256, the repository, the tag's commit and the workflow that built it. It is made with short-lived keys from GitHub's workflow identity, so there is no signing key to keep or lose. It proves where the file came from, not that the code is free of defects. GitHub documents this kind of attestation as SLSA build provenance at Build Level 2. Releases made before the workflow existed have no attestation.

The first release made this way was 0.9.0, and `gh attestation verify` succeeded on its bundle. After each release, record in the checkpoint report that it succeeded again.

## Why there is no .exe

A single-file executable built with a freezing tool bundles its own Python and is unsigned, which makes it look like malware to many security products and to Windows SmartScreen, and it asks people to run a binary they cannot read. The bundle is plain Python source that can be read before it is run, which suits a security tool. If a signed build is ever added, it will be documented here with how to verify it.
