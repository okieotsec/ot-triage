# Review log

This file records what the maintainer reviewed and tested by hand before each release, and the decisions made on security findings. It exists so that the statements in the README and `SECURITY.md` can be checked against something.

**What this is not.** It is a review by the maintainer, who is not independent of the project. It is not a third-party audit, and none has been done.

## How a review is done

- Changes written by the AI coding assistant are read as differences, with the assistant explaining each change until the maintainer understands what it does. The maintainer decides whether it is accepted.
- The maintainer runs the program by hand before a release: the interface, the calculation rules (checking that specific inputs give the intended results), and the limits of its protections (for example the file-size caps).
- Every security finding (from scanners, from AI reviews, or found by hand) gets a determination from the maintainer: fixed, accepted with a reason, or false positive with a reason. Findings and determinations are tracked in a private DefectDojo instance; a summary goes in the table below for each release.
- Work is planned and tracked in a private Vikunja board, and the maintainer marks it complete.

## Release record

A structured record starts with the first release after October 2026. Earlier releases were reviewed and tested the same way, but nothing was written down at the time.

| Date | Release | What was read | What was tested by hand | Findings decided | Sign-off |
| --- | --- | --- | --- | --- | --- |
| | | | | | |

## Written later, from memory (November 2026)

These entries are reconstructed. They are not contemporaneous records, and they are not complete.

- Before releases, the maintainer tested the interface and checked that the calculation rules gave the specific results they are meant to, and tested the limits of protections such as the file-size caps.
- The manual interface checklist left open at CP4 (`docs/GUI_TESTING.md`) was done by the maintainer on a real screen with a real keyboard.
