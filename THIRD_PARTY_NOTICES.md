# Third-party notices

## CVSS v4.0 scoring data

`cvss4_tables.py` contains the scoring tables of the official CVSS v4.0 calculator, converted mechanically from
`cvss_lookup.js`, `max_composed.js` and `max_severity.js` in
<https://github.com/FIRSTdotorg/cvss-v4-calculator>. The v4.0 scoring steps in `cvss.py` follow that project's
`cvss_score.js`.

```
Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## CVSS v3.0 and v3.1 scoring

The v3.0 and v3.1 formulas in `cvss.py` are implemented from the public CVSS specifications published by FIRST
(<https://www.first.org/cvss/>). FIRST's reference calculators are **not** included in this project; the developer tool
`tools/verify_cvss_against_reference.py` downloads them temporarily to confirm that every base vector scores
identically.
