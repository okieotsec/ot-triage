# Independent review by OpenAI Codex (AI), 2026-10-14

**What this is.** A review of OT Triage release 0.9.0 (tag `v0.9.0`, commit `e645bce`) by OpenAI's Codex command-line agent
(`codex-cli 0.162.0`, signed in with the owner's ChatGPT account), a different model from a different company than the one
that wrote the code. It is an **AI review**, not a human security audit.

**Files**
- `review-brief.md`: the brief Codex was given, written by the developer. It names the areas to look at and the output
  format, and tells the reviewer to form its own view before reading the project's own reports.
- `codex-report.md`: Codex's report, **exactly as returned**. Nothing in it was edited, shortened or re-ordered.
- The triage of every finding (what was verified, what was fixed, what was accepted and why) is in
  [../cp23-independent-review-fixes/claude.md](../cp23-independent-review-fixes/claude.md).

**How it was run.** From a fresh clone of the tag, with `codex exec -s read-only --ephemeral` and the brief on standard
input. Codex could read and run commands but could not change files. The clone was made with `--depth 1`, which is why the
report says the repository history is grafted and the full-history secret scan could not be checked by it: that is a
property of the review copy, not of the repository (gitleaks scans the full history in CI).

**Limits stated by the reviewer.** No network use; no real Nozomi or Dragos export; repository settings could not be
seen; the full test suite could not complete in its sandbox (no writable temporary folder or display), so 107 focused tests
were run; the generated CVSS 4.0 tables and purely visual GUI code received less attention.
