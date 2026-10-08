# GUI refresh proposal

Status: **approved and built** (see [GUI_TESTING.md](GUI_TESTING.md)). This page is kept as the design record. Where the finished GUI differs from the proposal, the differences are listed at the end.
Open [gui-mockup.html](gui-mockup.html) in a browser to click through all five views, in dark and light themes, at any window width. The mockup uses synthetic example data, and every number in it was produced by the real rules.

## Goals

1. Easier to use for someone who has never seen the tool.
2. Show *why* a result came out the way it did, in a way that is quick to read.
3. Make room for the new features: CVE lookup, threat data updates, settings.
4. Stay safe and accessible: no surprises on the network, nothing that depends on colour alone, usable from the keyboard.

## Decisions already made

- **Framework: stay on ttk** (standard Tkinter widgets with the existing custom dark theme, plus a light theme from the same colour tokens). No new dependency. See [ROADMAP.md](ROADMAP.md).
- **Navigation:** a sidebar with Assess, Batch, Threat data, Settings and About. Batch becomes a view instead of a pop-up window.

## The shell

```
┌────────────────────────────────────────────────────────────────┐
│ Vulnerability Prioritizer                    [⚠ Custom scoring] │  header
├──────────┬─────────────────────────────────────────────────────┤
│ Assess   │                                                     │
│ Batch    │               the active view                       │
│ Threat…  │                                                     │
│ Settings │                                                     │
│ About    │                                                     │
├──────────┴─────────────────────────────────────────────────────┤
│ ✓ KEV 2026.10.04 · 1 day   ✓ EPSS v2026.06.15 · 1 day  [Update] │  status bar
└────────────────────────────────────────────────────────────────┘
```

- The **status bar** is always visible. Its chips show how fresh each data source is: green when fresh, amber with a warning symbol when stale, grey when not loaded. Clicking a chip opens the Threat data view.
- The **Custom scoring** badge appears whenever any scoring setting differs from the defaults.
- Below about 900 pixels wide, the sidebar becomes a tab strip along the top and the two columns stack (the mockup shows this).

## Views

### 1. Assess

Left column: inputs. Right column: result.

- **CVE ID field (optional).** Typing a CVE and pressing Enter looks it up in the local KEV and EPSS data. Chips show what was found ("In CISA KEV", "EPSS 98th percentile"). If no data is loaded, the field says so and does not guess.
- **Threat input.** With a CVE and data loaded, the threat level is filled in automatically with its source shown ("Auto: from CISA KEV"). Two checkboxes (analyst-confirmed exploitation, public exploit known) can only *raise* it. "Override with a reason" opens a small dialog that requires a written reason; the reason is recorded in the summary. With no CVE, you pick the level yourself.
- **Inputs as segmented buttons**, not dropdowns. Every input has only two or three choices, so all choices are visible at once and one click sets a value. Labels are short ("Crown jewel", "None (end of life)"); the long definitions appear in a **? tooltip** on each input. The Low exposure tooltip carries the strict definition.
- **Result card:** a large bucket badge (NOW / NEXT / NEVER) with text, the headline, the ordering score bar, and **"why" chips**.
  - Chips are red with ▲ when a factor raises urgency (In KEV, Exposure: High, Crown jewel, No patch), green with ▼ when it lowers it (Strong controls), and grey with ▬ when it is neutral. Colour is never the only signal.
  - **Show reasoning** expands the full list of reasons, the inputs, the scoring settings in effect, and the KEV and EPSS versions used.
- **Recommended action:** includes CISA's required action when the CVE is in KEV.
- **What would change this?** Re-runs the rules once for each single alternative input and lists the ones that would move the bucket ("NEXT if the threat were None"). For CVSS it finds the nearest score that changes the result. If nothing moves it, it says so. Because it uses the real rules, it can never disagree with the result.
- **Copy summary** (plain text) and **Copy as Markdown** (for tickets).

### 2. Batch

- **Open CSV…** and **Export ranked CSV**. The file name, row count and the threat data versions used are shown.
- **Counters are filters:** click Now, Next, Never or Error to filter the table; click All to reset.
- **Search box** over ID, name and CVE. **Sortable columns.** Rows show a symbol and the word as well as a colour (▲ NOW, ▬ NEXT, ▼ NEVER, ! ERROR).
- **Details pane** for the selected row, with the same chips and reasoning as Assess.
- Large files load in the background with a progress line, so the window stays responsive (the 50,000-row limit stays).

### 3. Threat data

- One card per source: version, release or score date, when it was retrieved, entry count, and a Fresh, Stale or Not loaded state.
- **Update threat data** and **Import from files…**. The first update shows exactly what will be contacted (the two hosts, over HTTPS) and asks for confirmation.
- Updates run in the background with a progress line and a **Cancel** button. The result of each source is listed, including "the previous copy was kept" on failure.
- A short offline-use explanation, and the optional checkbox **Update threat data when the app starts** (off by default).

### 4. Settings

- The four scoring settings, each with its description, default and allowed range, and inline error messages (for example when the Critical line is not at least 0.5 above the High line).
- **Save**, and **Restore defaults…** with a confirmation prompt.
- A separate **Appearance** card: theme (dark or light) and text size (90%, 100%, 115%, 130%). These are saved in their own file, apart from the scoring settings, so changing the theme can never make a result look "custom".

### 5. About

Version, the offline statement, the Low exposure definition, where the Now / Next / Never categories come from (using your draft attribution text), and links to the documentation. The source links in your draft still need checking before publication.

## Accessibility

- Text contrast of at least 4.5:1 in both themes (the badge text colours are already chosen for this).
- Colour is never the only signal: every status has a symbol and a word.
- Everything works from the keyboard: Tab order follows reading order; arrow keys move within a segmented control; **Ctrl+1 to Ctrl+5** switch views; **Ctrl+L** focuses the CVE field; **Ctrl+Shift+C** copies the summary; Enter looks up the CVE. Focus is always visibly outlined.
- Text size setting (90% to 130%) scales fonts and row heights.
- Honest limit: Tkinter has weak screen reader support on most platforms. I can make the keyboard and contrast story strong, but I cannot promise full screen reader compatibility.

## Safety and behaviour rules

- No network access unless a button is pressed (or the optional startup checkbox is on).
- Network and large-file work run in a background thread. Results come back to the window through a queue, because Tkinter is not thread-safe. A Cancel button stops a running update.
- Errors are shown as short messages. Stack traces are never shown to the user.
- A CVE with no loaded data is never presented as "no known exploitation"; the interface says the data is missing.
- Anything that came from threat data (KEV text) is shown as plain text.

## Code structure

The current single file grows too big, so the GUI is split into small modules, consistent with the flat layout:

| Module | Contents | Needs a display to test? |
| --- | --- | --- |
| `explain.py` | Pure logic: the "what would change" analysis, summary and Markdown text, chip data | No |
| `uiprefs.py` | Theme, text size and the startup-update flag, loaded and saved with the same strict validation as the scoring settings | No |
| `gui_theme.py` | Colour tokens for dark and light, fonts, ttk style setup | Yes |
| `gui_widgets.py` | Segmented control, chip, tooltip, card, status bar, background worker | Yes |
| `gui_assess.py`, `gui_batch.py`, `gui_threat.py`, `gui_settings.py`, `gui_about.py` | One view each | Yes |
| `vuln_prioritizer_gui.py` | Window shell, navigation, shortcuts | Yes |

One small change to the core: `Result` gets a `factors` list (label plus raise, lower or neutral) so chips come from the rules themselves instead of being guessed from reason text. Bucket results are unchanged, and the existing tests keep passing.

## Testing plan

- `explain.py` and `uiprefs.py` get ordinary unit tests, including malformed preference files and a check that "what would change" always agrees with `prioritize`.
- Each view gets a smoke test on a real display: build it, drive its variables, and assert on what the widgets show. These tests skip cleanly when no display is available.
- A manual checklist covers keyboard-only use, both themes, every text size, and a 1366x768 screen.
- Security checkpoint **CP3** covers the settings screen and preference file handling, the background update worker (races, cancellation, a failure mid-update), and the confirmation flow.

## Milestones

Each milestone ends with all tests passing and a commit.

1. **Foundation:** `Result.factors`, `explain.py`, `uiprefs.py`, theme, widgets, window shell with navigation and the status bar.
2. **Assess view** with CVE lookup, chips, what-would-change, and both copy buttons.
3. **Batch view** with filters, search, sorting and the background loader.
4. **Threat data view** with the background updater and cancel.
5. **Settings and About views**, and the startup-update option.
6. **Accessibility pass, polish and CP3.**

## Decisions I need from you

| # | Question | My recommendation |
| --- | --- | --- |
| 1 | Segmented buttons instead of dropdowns for the five inputs? | Yes |
| 2 | Default theme: dark, with a light option? (Tkinter cannot reliably detect the system theme.) | Yes, dark by default |
| 3 | Include the "update on startup" option, off by default? | Yes, as in your notes |
| 4 | Keep appearance preferences in a separate file from the scoring settings? | Yes |
| 5 | Add `factors` to `Result` so chips come from the rules? | Yes |
| 6 | Show a short "Override with a reason" dialog for lowering a KEV threat level? | Yes, and record the reason in every summary and export |
| 7 | Any view, label or feature you want added, removed or renamed? | Tell me after looking at the mockup |

## What changed during the build

- **Choices run least to most concerning** (None, Public exploit, Active), matching the mockup. The first build had them reversed; a test now pins the order.
- **Disabled buttons** get a distinct, readable look instead of dimmed text on a coloured button.
- **Scroll areas** show their scrollbar only when the content is taller than the window.
- **Threat data status** is read cheaply from file headers and metadata, so the status bar does not parse all of EPSS.
- **Batch results scored under older settings** are flagged, so a settings change never silently leaves stale rankings looking current.
- **Window size:** tiling window managers may ignore the requested size; the layout switches to the narrow form by the window's real width.

## Visual polish after the first build

The first build was functional but flatter than the mockup. A second pass, checked against screenshots of the running app, added:

- **A modern typeface:** the best installed of Inter, Adwaita Sans, Cantarell and Noto Sans, instead of the default Arial-like font, with slightly larger text.
- **Rounded shapes:** cards, buttons, chips (pills), the priority badge, segmented controls, inputs and the Batch counters now have anti-aliased rounded corners. Tk 8.6 cannot draw these natively, so small images are generated in pure Python (no third-party packages) and used as backgrounds or corner overlays.
- **A refined sidebar:** an accent bar marks the current view and the keyboard shortcut is shown at the right of each item, instead of a boxed outline.
- **Roomier, more consistent spacing** between cards and fields.
- **A bug fix found along the way:** in Tk, a frame that contains the focused widget draws its focus colour (black by default) as its border. Cards containing the focused field had a black outline; every bordered frame now uses its own border colour for focus too.
