"""Anti-aliased rounded shapes for Tk 8.6, built from small generated PNG images (standard library only)."""
import base64
import math
import struct
import tkinter as tk
import tkinter.font as tkfont
import zlib

SAMPLES = 4


def _rgb(color):
    return tuple(int(color[i:i + 2], 16) for i in (1, 3, 5))


def shape_rgba(width, height, radius, fill=None, ring=None, ring_width=1, outside=None):
    """Return rows of (r, g, b, a) pixels for a rounded rectangle.

    fill is the inside colour, ring the border colour and outside the colour beyond the shape; any of them may be
    None, meaning transparent. Edges are anti-aliased by supersampling.
    """
    radius = max(1, min(radius, width // 2, height // 2))
    palette = {"fill": _rgb(fill) if fill else None, "ring": _rgb(ring) if ring else None,
               "outside": _rgb(outside) if outside else None}
    inner_w = ring_width if ring else 0
    rows = []
    for py in range(height):
        row = []
        for px in range(width):
            row.append(_pixel(px, py, width, height, radius, inner_w, palette))
        rows.append(row)
    return rows


def _pixel(px, py, width, height, radius, ring_width, palette):
    near_edge = (px < radius + 1 or px >= width - radius - 1 or py < ring_width + 1 or py >= height - ring_width - 1)
    if not near_edge:
        return _solid(palette["fill"])
    total, covered = [0, 0, 0], 0
    for iy in range(SAMPLES):
        for ix in range(SAMPLES):
            x, y = px + (ix + 0.5) / SAMPLES, py + (iy + 0.5) / SAMPLES
            cx = min(max(x, radius), width - radius)
            cy = min(max(y, radius), height - radius)
            distance = math.hypot(x - cx, y - cy)
            if distance <= radius - ring_width:
                kind = "fill"
            elif distance <= radius:
                kind = "ring" if palette["ring"] else "fill"
            else:
                kind = "outside"
            colour = palette[kind]
            if colour is not None:
                covered += 1
                total[0] += colour[0]
                total[1] += colour[1]
                total[2] += colour[2]
    if not covered:
        return (0, 0, 0, 0)
    return (total[0] // covered, total[1] // covered, total[2] // covered, round(255 * covered / SAMPLES ** 2))


def _solid(colour):
    return (0, 0, 0, 0) if colour is None else (*colour, 255)


def png_bytes(rows):
    """Encode rows of RGBA pixels as a PNG file."""
    height, width = len(rows), len(rows[0])
    raw = b"".join(b"\x00" + bytes(channel for pixel in row for channel in pixel) for row in rows)

    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def _cache(widget):
    root = widget.winfo_toplevel()
    if not hasattr(root, "_round_images"):
        root._round_images = {}
    return root._round_images


def photo(widget, width, height, radius, fill=None, ring=None, ring_width=1, outside=None):
    """Return a cached PhotoImage of a rounded rectangle."""
    key = (width, height, radius, fill, ring, ring_width, outside)
    cache = _cache(widget)
    if key not in cache:
        rows = shape_rgba(width, height, radius, fill, ring, ring_width, outside)
        cache[key] = tk.PhotoImage(master=widget, data=base64.b64encode(png_bytes(rows)))
    return cache[key]


def corner_photo(widget, which, radius, ring, outside, ring_width=1, fill=None):
    """Return the image for one corner (tl, tr, bl, br) of a rounded frame.

    A widget cannot show what is behind it, so fill is the opaque colour inside the corner (the frame's own colour).
    """
    key = ("corner", which, radius, ring, outside, ring_width, fill)
    cache = _cache(widget)
    if key not in cache:
        rows = shape_rgba(radius * 2, radius * 2, radius, fill, ring, ring_width, outside)
        rows = rows[:radius] if which[0] == "t" else rows[radius:]
        rows = [row[:radius] if which[1] == "l" else row[radius:] for row in rows]
        cache[key] = tk.PhotoImage(master=widget, data=base64.b64encode(png_bytes(rows)))
    return cache[key]


def _fills(fill):
    """Expand a single colour, or a dict keyed by corner, into a colour for each corner."""
    if isinstance(fill, dict):
        return fill
    return dict.fromkeys(("tl", "tr", "bl", "br"), fill)


def round_corners(frame, radius, ring, outside, ring_width=1, fill=None):
    """Hide the square corners of a bordered widget by overlaying small anti-aliased corner images.

    The overlays are placed against the widget's outer edge, so this works for frames, entries and canvases alike.
    """
    frame.corner_labels = []
    placements = {"tl": {"x": 0, "y": 0}, "tr": {"relx": 1.0, "x": -radius, "y": 0},
                  "bl": {"x": 0, "rely": 1.0, "y": -radius},
                  "br": {"relx": 1.0, "x": -radius, "rely": 1.0, "y": -radius}}
    fills = _fills(fill)
    for which, where in placements.items():
        image = corner_photo(frame, which, radius, ring, outside, ring_width, fills[which])
        label = tk.Label(frame, image=image, bd=0, highlightthickness=0, bg=outside)
        label.place(bordermode="outside", **where)
        label.image = image
        frame.corner_labels.append(label)
    return frame.corner_labels


def recolor_corners(frame, radius, ring, outside, ring_width=1, fill=None):
    """Change the ring or inside colours of the corner overlays made by round_corners."""
    fills = _fills(fill)
    for which, label in zip(("tl", "tr", "bl", "br"), frame.corner_labels, strict=True):
        image = corner_photo(frame, which, radius, ring, outside, ring_width, fills[which])
        label.configure(image=image)
        label.image = image


def text_size(widget, font, text):
    """Return the pixel width and line height of text in a font."""
    measured = tkfont.Font(root=widget, font=font)
    return measured.measure(text), measured.metrics("linespace")


def shape_label(parent, text, font, fg, fill=None, ring=None, outside=None, radius=None, padx=12, pady=4,
                min_width=0, ring_width=1, **options):
    """Create a label whose background is a rounded rectangle (a pill when radius is None)."""
    outside = outside or parent.cget("bg")
    text_w, text_h = text_size(parent, font, text)
    width, height = max(text_w + 2 * padx, min_width), text_h + 2 * pady
    corner = height // 2 if radius is None else radius
    image = photo(parent, width, height, corner, fill, ring, ring_width, None)
    label = tk.Label(parent, text=text, font=font, fg=fg, bg=outside, image=image, compound="center", bd=0,
                     highlightthickness=0, padx=0, pady=0, **options)
    label.image = image
    label.shape = {"fill": fill, "ring": ring, "radius": corner}
    return label
