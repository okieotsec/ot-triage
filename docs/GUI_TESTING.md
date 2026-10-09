# GUI testing

## Automated tests

Run everything with `python3 -m unittest` (about 80 seconds, mostly the tests that open real windows). Tests that need a display skip themselves when none is available.

| Area | File | What it checks |
| --- | --- | --- |
| Colours and contrast | `test_gui_theme.py` | Every text and background pair meets a 4.5:1 contrast ratio in both themes, disabled text stays readable, every status has a symbol as well as a colour |
| Logic behind the screens | `test_explain.py`, `test_uiprefs.py` | The "what would change" list agrees with the real rules, summaries include inputs, settings and data versions, malformed preference files fall back safely |
| Rounded shapes | `test_gui_round.py` | The generated anti-aliased corners and pills are correct pixel by pixel, are placed exactly on the corners of frames, entries and canvases, and the PNG encoding is valid |
| CVSS | `test_cvss.py` | The vector parser, well-known scores, agreement with the official FIRST calculators for all 110,160 base vectors, and rejection of hostile text |
| Widgets | `test_gui_widgets.py` | Segmented controls by mouse and keyboard, chips that wrap, tooltips, expanders, the scrolling area, the background worker and the reason dialog |
| Assess | `test_gui_assess.py` | Results match the rules, CVE lookup and the threat sources, flags can only raise the level, overrides need a reason, tab order, text size |
| Batch | `test_gui_batch.py` | Loading, filters, search, sorting, export, hostile files, a 20,000-row file, a load that finishes after the window was rebuilt |
| Threat data | `test_gui_threat.py` | Confirmation before any download, progress and cancel, failures keep the previous copy, stale and damaged data |
| Settings and About | `test_gui_settings.py` | Live validation, save and restore with confirmation, failed saves, appearance preferences |
| Window shell | `test_gui_app.py` | Navigation, shortcuts, theme rebuild that keeps the user's place, the status bar, hostile settings and preference files, startup update |

The tests never touch the network (any attempt fails the test) and never write to your real settings or data folders; every test uses temporary folders.

## Manual checklist

Run this before a release, with `python3 ot_triage_gui.py`.

**Keyboard only (no mouse)**
- [ ] Tab reaches every field, button and choice in a sensible order; the focused control has a visible outline.
- [ ] Left and Right arrows change a focused choice (for example Threat or Exposure).
- [ ] Ctrl+1 to Ctrl+5 switch views; Ctrl+L focuses the CVE field; Ctrl+Shift+C copies the summary; after looking up a KEV CVE the References card (and the Batch Details box for a row with a KEV `cve`) lists links that open in your browser when clicked (and from the keyboard with Enter); Ctrl+plus, Ctrl+minus and Ctrl+0 change the text size, keep what you typed, and the size is still there after a restart.
- [ ] Enter in the CVE field looks the CVE up; Space or Enter opens "Show reasoning".

**Both themes and every text size**
- [ ] Settings, Appearance: try Dark and Light, then 90%, 100%, 115% and 130%.
- [ ] Nothing overlaps or is cut off, and the scrollbar appears only when content does not fit.
- [ ] Your inputs and the current view survive each change.

**Small screen**
- [ ] At about 1366x768, or with the window narrowed below 900 pixels, the sidebar becomes a tab strip along the top and the two Assess columns stack.

**Meaning, not only colour**
- [ ] Every status shows a symbol and a word (▲ NOW, ▬ NEXT, ▼ NEVER, ! ERROR, ✓ Fresh, ⚠ Stale).

**Threat data**
- [ ] With no data, the status bar says "not loaded" and a CVE lookup says so instead of saying the CVE is safe.
- [ ] Update asks for confirmation and names the two hosts; Cancel stops it; a failed update keeps the old copy.
- [ ] Import from files works with a downloaded KEV JSON and EPSS file, and rejects a wrong file with a clear message.

**Known limit**
- Tkinter has weak screen reader support on most platforms. Keyboard use and contrast are covered above; screen reader use is not guaranteed.
