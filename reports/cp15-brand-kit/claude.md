Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP15 (OkieOTSec brand kit v1.1 in the application) / branch brand-kit, before merge
Scope: image files from a downloaded zip (the project owner's brand kit) now ship in the repository under assets/brand/ and are loaded by the application (window icon, header shield, About lockup); the theme colours follow the kit's tokens; the README banner and screenshots are replaced; the bundle builder includes assets/. A downloaded archive is untrusted input, so the kit was inspected before use.
Tools run (with versions): bandit 1.9.4, semgrep 1.179.0 (p/python, p/security-audit), ruff 0.16.10, gitleaks (full history), the full suite (872 tests, on a private virtual display), rsvg-convert 2.62.3 (to render the PNGs), PNG chunk and SVG content scans
Tools not run (and why): osv-scanner and pip-audit (no dependencies); mitmproxy and atheris (no network code, no new parser)

Tool results (attached under reports/cp15-brand-kit/)
- bandit: 0 findings. semgrep: 0 findings. ruff: 0 findings. gitleaks: no leaks.

What was checked
- The zip was listed before it was unpacked, unpacked into its own empty folder outside the project, and read from there. Every SVG was parsed and scanned: only shape, group, path, circle, rect, title and filter elements; no script, event handler, javascript: link, foreignObject, external reference or import. Every PNG in the kit has only standard image chunks (no text, EXIF or content-credentials blocks).
- What was added to the repository: the SVGs the application and README use, PNGs rendered from them by rsvg-convert at the sizes needed (Tk cannot read SVG), the kit's favicon.ico, the link-preview card and the kit's tokens. Not added: the PDF brand guide and BRAND.md, because they contain the owner's real name for use on talk slides, which the project keeps out of the repository.
- Tests (new): every image the code asks for exists and is a PNG of the size it is named for; every SVG in the repository holds no script or outside reference; every PNG carries only standard chunks (the converter's harmless background-colour chunk is allowed); the header shield and lockup follow the theme and the text size; and with the image folder missing the application still starts, simply without pictures.
- The window icon, header shield and lockup are loaded from files next to the program and nothing else; a missing or corrupt file is skipped, never an error. No network access and nothing is generated at run time.
- A bug I introduced and found by looking at a screenshot: the two extra rows added to the Batch view in earlier changes left room for only one table row at the default window size. The Findings / By asset toggle now sits on the counters row, the details box is shorter, and five rows are visible again (the screenshots in the README show it).
- Theme: the dark and light themes use the kit's token values for surface, line, text and muted colours; every text pair still passes the project's contrast test, and the risk colours are unchanged.

Findings: none (the layout regression above was caused by this work's predecessor and fixed in the same change).

Release gate for this feature
| Gate | Evidence | Pass |
| --- | --- | --- |
| The downloaded kit is inspected before use | scans of every SVG and PNG; unpacked outside the project | Yes |
| Nothing personal is added to the repository | the PDF and BRAND.md (which name a person) are left out | Yes |
| The application never fails because of an image | tests with the folder missing | Yes |
| Contrast and risk colours unchanged | the existing contrast tests pass | Yes |
| Static analysis clean | bandit, semgrep, ruff 0 findings; gitleaks clean | Yes |
| Documentation updated | assets/brand/README.md, README.md, CHANGELOG.md | Yes |
