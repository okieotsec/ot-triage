"""OkieOTSec branding for OT Triage: the logo images, the window icon, the wordmark and the public links.

The images come from the OkieOTSec brand kit (see assets/brand/README.md). Tk cannot read SVG, so the vector files
were turned into PNGs at the sizes the application needs. Nothing here depends on the images being present: if a
file is missing the application simply starts without that picture.
"""
import sys
import tkinter as tk
from pathlib import Path

BRAND_NAME = "OkieOTSec"
TAGLINE = "OT/ICS security from the radio tower to the control room."
LINKS = (("Website", "https://okieotsec.com"),
         ("GitHub", "https://github.com/okieotsec"),
         ("YouTube", "https://www.youtube.com/@OkieOTSec"),
         ("X", "https://x.com/okieotsec"))
ASSETS = Path(__file__).resolve().parent / "assets" / "brand"
ICON_SIZES = (256, 128, 64, 48, 32, 16)          # the app tile, as PNGs (the window icon)
HEADER_HEIGHTS = (32, 40, 48, 56, 64)            # the shield next to the title, for different text sizes
HEADER_HEIGHT = 40                               # at 100% text size
LOCKUP_WIDTHS = (240, 320, 400, 480)
FAVICON = ASSETS / "icons" / "favicon.ico"


def _photo(root, relative):
    """Load one brand image, or None if it is missing or unreadable."""
    try:
        return tk.PhotoImage(master=root, file=str(ASSETS / relative))
    except (tk.TclError, OSError):
        return None


def nearest(options, wanted):
    """The option closest to the wanted size."""
    return min(options, key=lambda option: abs(option - wanted))


def _theme_prefix(style):
    """The kit has one set of images for dark backgrounds and one for light ones."""
    return "-dark" if style.theme.name == "dark" else ""


def wordmark(parent, style, bg, size=11):
    """Return the OkieOTSec wordmark: the letters OT stand out in the accent colour."""
    t = style.theme
    box = tk.Frame(parent, bg=bg)
    font = style.font(size, "bold", "title")
    for text, colour in (("Okie", t.text), ("OT", t.accent), ("Sec", t.text)):
        tk.Label(box, text=text, font=font, bg=bg, fg=colour, padx=0, pady=0, bd=0).pack(side=tk.LEFT)
    return box


def header_logo(parent, style, bg):
    """Return a label showing the shield for the window header, or None if the image is not available."""
    height = nearest(HEADER_HEIGHTS, round(HEADER_HEIGHT * style.scale))
    image = _photo(parent, f"header/shield{_theme_prefix(style)}-{height}.png")
    if image is None:
        return None
    label = tk.Label(parent, image=image, bg=bg, bd=0, padx=0, pady=0)
    label.image = image                    # keep a reference, or Tk drops the picture
    return label


def lockup(parent, style, bg, width=320):
    """Return a label showing the shield-and-name lockup, or None if the image is not available."""
    wanted = nearest(LOCKUP_WIDTHS, round(width * style.scale))
    image = _photo(parent, f"lockup/lockup{_theme_prefix(style)}-{wanted}.png")
    if image is None:
        return None
    label = tk.Label(parent, image=image, bg=bg, bd=0, padx=0, pady=0)
    label.image = image
    return label


def app_icon(root):
    """Set the window icon for the application and its dialogs; the images are kept alive on the root."""
    images = [image for image in (_photo(root, f"icons/tile-{size}.png") for size in ICON_SIZES) if image is not None]
    if not images:
        return None
    try:
        root.iconphoto(True, *images)
    except tk.TclError:
        return None  # some window managers have no icon support; the application works the same without one
    if sys.platform == "win32" and FAVICON.is_file():
        try:
            root.iconbitmap(default=str(FAVICON))
        except tk.TclError:
            pass
    root.app_icons = images
    return images
