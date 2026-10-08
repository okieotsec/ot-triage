import struct
import tkinter as tk
import unittest
import zlib

import gui_round as gr
from gui_testing import DisplayTestCase


def decode_png(data):
    """Decode a PNG made by png_bytes back into (width, height, rows of RGBA tuples)."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise AssertionError("not a PNG file")
    position, chunks = 8, {}
    while position < len(data):
        length, kind = struct.unpack(">I4s", data[position:position + 8])
        body = data[position + 8:position + 8 + length]
        crc = struct.unpack(">I", data[position + 8 + length:position + 12 + length])[0]
        if crc != zlib.crc32(kind + body) & 0xFFFFFFFF:
            raise AssertionError("bad chunk checksum")
        chunks.setdefault(kind, b"")
        chunks[kind] += body
        position += 12 + length
    width, height, depth, colour = struct.unpack(">IIBB", chunks[b"IHDR"][:10])
    if (depth, colour) != (8, 6):
        raise AssertionError("expected 8-bit RGBA")
    raw = zlib.decompress(chunks[b"IDAT"])
    stride = width * 4 + 1
    rows = []
    for y in range(height):
        if raw[y * stride] != 0:
            raise AssertionError("expected filter type 0")
        line = raw[y * stride + 1:(y + 1) * stride]
        rows.append([tuple(line[x * 4:x * 4 + 4]) for x in range(width)])
    return width, height, rows


class ShapePixelTests(unittest.TestCase):
    def test_png_round_trips(self):
        rows = gr.shape_rgba(20, 12, 5, "#1e293b", "#334155")
        width, height, decoded = decode_png(gr.png_bytes(rows))
        self.assertEqual((width, height), (20, 12))
        self.assertEqual(decoded, [[tuple(p) for p in row] for row in rows])

    def test_a_filled_shape_is_opaque_inside_and_transparent_outside_the_corners(self):
        rows = gr.shape_rgba(40, 30, 8, "#ff0000")
        self.assertEqual(rows[15][20], (255, 0, 0, 255))
        self.assertEqual(rows[0][0][3], 0)
        self.assertEqual(rows[29][39][3], 0)
        self.assertEqual(rows[15][0][3], 255)
        self.assertEqual(rows[0][20][3], 255)

    def test_edges_are_anti_aliased(self):
        rows = gr.shape_rgba(40, 30, 10, "#00ff00")
        partial = [p for row in rows[:10] for p in row[:10] if 0 < p[3] < 255]
        self.assertGreater(len(partial), 6)

    def test_a_ring_is_drawn_one_pixel_wide_along_straight_edges(self):
        rows = gr.shape_rgba(40, 30, 8, "#111111", "#aaaaaa")
        self.assertEqual(rows[0][20], (170, 170, 170, 255))
        self.assertEqual(rows[15][0], (170, 170, 170, 255))
        self.assertEqual(rows[29][20], (170, 170, 170, 255))
        self.assertEqual(rows[15][39], (170, 170, 170, 255))
        self.assertEqual(rows[1][20], (17, 17, 17, 255))
        self.assertEqual(rows[15][1], (17, 17, 17, 255))

    def test_a_ring_only_shape_is_transparent_inside(self):
        rows = gr.shape_rgba(40, 24, 12, None, "#ff00ff")
        self.assertEqual(rows[12][20][3], 0)
        self.assertEqual(rows[0][20], (255, 0, 255, 255))

    def test_an_outside_colour_fills_the_corner_cut_away(self):
        rows = gr.shape_rgba(30, 30, 8, None, "#ffffff", 1, "#0f172a")
        self.assertEqual(rows[0][0], (15, 23, 42, 255))
        self.assertEqual(rows[15][15][3], 0)

    def test_corners_are_symmetric(self):
        rows = gr.shape_rgba(30, 30, 9, "#123456", "#abcdef", 1, "#000000")
        for y in range(30):
            for x in range(30):
                self.assertEqual(rows[y][x], rows[y][29 - x], (x, y))
                self.assertEqual(rows[y][x], rows[29 - y][x], (x, y))

    def test_a_pill_has_semicircle_ends(self):
        rows = gr.shape_rgba(60, 20, 10, "#ffffff")
        self.assertEqual(rows[10][0][3], 255)
        self.assertEqual(rows[0][0][3], 0)
        self.assertEqual(rows[0][30][3], 255)

    def test_radius_is_limited_to_half_the_smaller_side(self):
        rows = gr.shape_rgba(20, 10, 99, "#ffffff")
        self.assertEqual(rows[5][10][3], 255)
        self.assertEqual(rows[0][0][3], 0)

    def test_tiny_shapes_do_not_crash(self):
        for w, h, r in ((2, 2, 1), (3, 5, 1), (1, 1, 1), (4, 4, 50)):
            rows = gr.shape_rgba(w, h, r, "#ffffff", "#000000")
            self.assertEqual((len(rows), len(rows[0])), (h, w))


class ShapeImageTests(DisplayTestCase):
    def test_photos_have_the_requested_size_and_are_cached(self):
        a = gr.photo(self.root, 80, 24, 12, "#ffffff", "#000000")
        b = gr.photo(self.root, 80, 24, 12, "#ffffff", "#000000")
        self.assertIs(a, b)
        self.assertEqual((a.width(), a.height()), (80, 24))
        self.assertIsNot(a, gr.photo(self.root, 80, 24, 12, "#ff0000", "#000000"))

    def test_corner_photos_are_radius_squares(self):
        for which in ("tl", "tr", "bl", "br"):
            image = gr.corner_photo(self.root, which, 10, "#334155", "#0f172a", 1, "#1e293b")
            self.assertEqual((image.width(), image.height()), (10, 10), which)

    def test_corner_photos_are_mirror_images(self):
        tl = gr.corner_photo(self.root, "tl", 10, "#334155", "#0f172a", 1, "#1e293b")
        br = gr.corner_photo(self.root, "br", 10, "#334155", "#0f172a", 1, "#1e293b")
        self.assertEqual(tl.get(0, 0), br.get(9, 9))
        self.assertEqual(tl.get(0, 9), br.get(9, 0))

    def test_corner_photos_are_opaque_inside_so_the_frame_colour_shows_through(self):
        image = gr.corner_photo(self.root, "tl", 10, "#334155", "#0f172a", 1, "#1e293b")
        self.assertEqual(self.root.tk.call(image, "transparency", "get", 9, 9), 0)
        self.assertEqual(image.get(9, 9), (30, 41, 59))
        self.assertEqual(image.get(0, 0), (15, 23, 42))

    def test_per_corner_fills_are_used(self):
        frame = self.make_frame()
        box = tk.Frame(frame, bg="#000000", highlightthickness=1, width=100, height=60)
        box.place(x=10, y=10)
        labels = gr.round_corners(box, 8, "#334155", "#0f172a", fill={"tl": "#ff0000", "tr": "#00ff00",
                                                                     "bl": "#0000ff", "br": "#ffff00"})
        self.assertEqual([lbl.image.get(7, 7) if i in (0, 2) else lbl.image.get(0, 7)
                          for i, lbl in enumerate(labels)][:1], [(255, 0, 0)])
        self.assertEqual(labels[1].image.get(0, 7), (0, 255, 0))
        gr.recolor_corners(box, 8, "#aabbcc", "#0f172a", 1, "#123456")
        self.assertEqual(labels[3].image.get(0, 0), (18, 52, 86))

    def test_round_corners_places_four_overlays_at_the_corners(self):
        frame = self.make_frame(300, 200)
        box = tk.Frame(frame, bg="#1e293b", highlightthickness=1, highlightbackground="#334155", width=200, height=100)
        box.place(x=20, y=20)
        labels = gr.round_corners(box, 10, "#334155", "#0f172a", fill="#1e293b")
        self.root.update()
        self.assertEqual(len(labels), 4)
        positions = sorted((lbl.winfo_x(), lbl.winfo_y()) for lbl in labels)
        self.assertEqual(positions[0], (0, 0))
        self.assertEqual(max(x for x, _y in positions), box.winfo_width() - 10)
        self.assertEqual(max(y for _x, y in positions), box.winfo_height() - 10)

    def test_overlays_sit_exactly_on_the_corners_of_every_kind_of_widget(self):
        frame = self.make_frame(400, 300)
        makers = {"frame": lambda: tk.Frame(frame, highlightthickness=1, width=120, height=60),
                  "thick frame": lambda: tk.Frame(frame, highlightthickness=2, width=120, height=60),
                  "entry": lambda: tk.Entry(frame, highlightthickness=2, relief="flat", width=12),
                  "entry with border": lambda: tk.Entry(frame, highlightthickness=2, bd=1, relief="flat", width=12),
                  "canvas": lambda: tk.Canvas(frame, highlightthickness=2, width=120, height=60)}
        for name, make in makers.items():
            widget = make()
            widget.pack(pady=4)
            labels = gr.round_corners(widget, 8, "#334155", "#0f172a", 2, "#1e293b")
            self.root.update()
            width, height = widget.winfo_width(), widget.winfo_height()
            tl, tr, bl, br = labels
            self.assertEqual((tl.winfo_x(), tl.winfo_y()), (0, 0), name)
            self.assertEqual((tr.winfo_x() + 8, tr.winfo_y()), (width, 0), name)
            self.assertEqual((bl.winfo_x(), bl.winfo_y() + 8), (0, height), name)
            self.assertEqual((br.winfo_x() + 8, br.winfo_y() + 8), (width, height), name)

    def test_a_shape_label_fits_its_text_and_keeps_the_label_api(self):
        frame = self.make_frame()
        label = gr.shape_label(frame, "▲ In CISA KEV", self.style.font(9), "#f87171", ring="#f87171")
        label.pack()
        self.root.update()
        self.assertEqual(label.cget("text"), "▲ In CISA KEV")
        self.assertEqual(str(label.cget("fg")), "#f87171")
        self.assertEqual(label.winfo_reqheight(), label.image.height())
        self.assertGreater(label.winfo_reqwidth(), 60)
        self.assertEqual(label.shape["radius"], label.image.height() // 2)

    def test_longer_text_makes_a_wider_pill(self):
        frame = self.make_frame()
        short = gr.shape_label(frame, "KEV", self.style.font(9), "#ffffff", ring="#ffffff")
        long = gr.shape_label(frame, "Elevated EPSS (97th percentile)", self.style.font(9), "#ffffff", ring="#ffffff")
        self.assertGreater(long.image.width(), short.image.width() + 60)
        self.assertEqual(long.image.height(), short.image.height())

    def test_minimum_width_is_respected(self):
        frame = self.make_frame()
        label = gr.shape_label(frame, "-", self.style.font(30, "bold"), "#fff", fill="#dc2626", min_width=200)
        self.assertGreaterEqual(label.image.width(), 200)


if __name__ == "__main__":
    unittest.main()
