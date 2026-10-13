# OkieOTSec brand assets

The logo, icons and colour tokens used by OT Triage, from the OkieOTSec brand kit v1.1.

- `svg/`: the vector originals used here (lockups, shields, app tile, wordmarks, README badge). The Oklahoma outline is
  traced from US Census Bureau boundary data and must not be redrawn by hand.
- `icons/`, `header/`, `lockup/`: PNGs rendered from those SVGs at the sizes the application needs (Tk cannot read
  SVG): the window icon (the app tile), the shield beside the title, and the lockup in the About view.
  `icons/favicon.ico` is the Windows icon.
- `readme/` and `social/`: the lockups shown in the README and the 1200 x 630 link-preview card.
- `tokens.json` and `tokens.css`: the colours and fonts the application's themes are built from.

To rebuild the PNGs from the SVGs: `rsvg-convert -w <size> -h <size> svg/okieotsec-app-tile.svg -o icons/tile-<size>.png`
(and likewise for the shields by height and the lockups by width).

**Rights.** The MIT licence of this repository covers the code. The OkieOTSec name, logo and brand assets are not
offered under it: please ask before using them for anything other than referring to this project.
