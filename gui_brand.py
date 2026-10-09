"""OkieOTSec branding for OT Triage: the wordmark, the window icon and the project's public links."""
import base64
import tkinter as tk

from gui_round import png_bytes, shape_rgba
from gui_theme import DARK

BRAND_NAME = "OkieOTSec"
TAGLINE = "OT/ICS security from the radio tower to the control room."
LINKS = (("Website", "https://okieotsec.com"),
         ("GitHub", "https://github.com/okieotsec"),
         ("YouTube", "https://www.youtube.com/@OkieOTSec"),
         ("X", "https://x.com/okieotsec"))
ICON_SIZES = (64, 32, 16)


def wordmark(parent, style, bg, size=11):
    """Return the OkieOTSec wordmark: the letters OT stand out in the accent colour."""
    t = style.theme
    box = tk.Frame(parent, bg=bg)
    font = style.font(size, "bold")
    for text, colour in (("Okie", t.text), ("OT", t.accent), ("Sec", t.text)):
        tk.Label(box, text=text, font=font, bg=bg, fg=colour, padx=0, pady=0, bd=0).pack(side=tk.LEFT)
    return box


def _over(canvas, shape, left, top):
    """Paint a small RGBA shape onto the canvas with normal alpha blending."""
    for y, row in enumerate(shape):
        for x, pixel in enumerate(row):
            alpha = pixel[3]
            if not alpha:
                continue
            base = canvas[top + y][left + x]
            if not base[3]:
                canvas[top + y][left + x] = pixel
                continue
            weight = alpha / 255
            pairs = zip(pixel[:3], base[:3], strict=True)
            blended = tuple(round(new * weight + old * (1 - weight)) for new, old in pairs)
            canvas[top + y][left + x] = (*blended, max(base[3], alpha))


def icon_rows(size):
    """Return the icon as rows of RGBA pixels: three bars (red, amber, green) on a navy rounded square."""
    unit = size / 64
    canvas = [[(0, 0, 0, 0)] * size for _ in range(size)]
    _over(canvas, shape_rgba(size, size, max(2, round(14 * unit)), DARK.bg, DARK.accent, max(1, round(2.5 * unit))),
          0, 0)
    bar_height, gap, left = max(2, round(9 * unit)), max(1, round(6 * unit)), round(13 * unit)
    top = round((64 - (3 * 9 + 2 * 6)) / 2 * unit)
    for index, (colour, length) in enumerate(((DARK.now, 38), (DARK.next, 29), (DARK.never, 20))):
        width = max(3, round(length * unit))
        _over(canvas, shape_rgba(width, bar_height, bar_height // 2, colour), left, top + index * (bar_height + gap))
    return canvas


def app_icon(root):
    """Set the window icon for the application and its dialogs; the image is kept alive on the root."""
    images = [tk.PhotoImage(master=root, data=base64.b64encode(png_bytes(icon_rows(size)))) for size in ICON_SIZES]
    try:
        root.iconphoto(True, *images)
    except tk.TclError:
        return None  # some window managers have no icon support; the application works the same without one
    root.app_icons = images
    return images
