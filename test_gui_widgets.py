import threading
import time
import tkinter as tk
import unittest
from unittest import mock

import gui_widgets as gw
import references as refs
from gui_testing import DisplayTestCase


class WidgetTests(DisplayTestCase):
    def test_card_and_buttons(self):
        frame = self.make_frame()
        inner = gw.card(frame, self.style, "Vulnerability")
        self.assertIsInstance(inner, tk.Frame)
        clicked = []
        for kind in ("primary", "secondary"):
            gw.button(inner, self.style, kind, lambda: clicked.append(1), kind).invoke()
        self.assertEqual(len(clicked), 2)

    def test_disabled_buttons_look_disabled_and_readable(self):
        frame = self.make_frame()
        clicked = []
        for kind in ("primary", "secondary"):
            b = gw.button(frame, self.style, "Save", lambda: clicked.append(1), kind)
            enabled_look = (b.fill, str(b.cget("fg")), str(b.cget("image")))
            gw.set_enabled(b, False)
            self.assertEqual(str(b.cget("state")), "disabled")
            self.assertEqual((b.fill, str(b.cget("fg"))), (self.style.theme.border, self.style.theme.muted))
            self.assertNotEqual((b.fill, str(b.cget("fg")), str(b.cget("image"))), enabled_look)
            b.invoke()
            gw.set_enabled(b, True)
            self.assertEqual((b.fill, str(b.cget("fg")), str(b.cget("image"))), enabled_look)
            self.assertEqual(str(b.cget("state")), "normal")
            b.invoke()
        self.assertEqual(len(clicked), 2)

    def test_chips_carry_a_symbol_and_a_word(self):
        frame = self.make_frame()
        for direction, symbol in (("raise", "\u25b2"), ("lower", "\u25bc"), ("neutral", "\u25ac"), ("ok", "\u2713"),
                                  ("warn", "\u26a0")):
            chip = gw.chip(frame, self.style, "In CISA KEV", direction)
            self.assertEqual(chip.cget("text"), f"{symbol} In CISA KEV")
            self.assertEqual(str(chip.cget("fg")), self.style.direction(direction))

    def test_flow_frame_wraps_chips_to_the_width(self):
        frame = self.make_frame()
        flow = gw.FlowFrame(frame, self.style.theme.card)
        flow.place(x=0, y=0, width=260)
        self.root.update()
        one_row = gw.chip(flow, self.style, "In CISA KEV").winfo_reqheight()
        flow.set_items([gw.chip(flow, self.style, f"Factor number {i}", "raise") for i in range(8)])
        self.pump(0.2)
        self.assertGreater(int(flow.cget("height")), one_row * 2)
        for item in flow.items:
            self.assertLessEqual(item.winfo_x() + item.winfo_reqwidth(), flow.winfo_width() + 1)
        flow.set_items([])
        self.assertEqual(flow.items, [])

    def test_segmented_control_by_mouse_and_keyboard(self):
        frame = self.make_frame()
        var = tk.StringVar(value="a")
        changes = []
        seg = gw.Segmented(frame, self.style, [("a", "Alpha"), ("b", "Beta"), ("c", "Gamma")], var,
                           lambda: changes.append(var.get()))
        seg.pack(fill=tk.X)
        self.root.update()
        seg.buttons["c"].event_generate("<Button-1>")
        self.pump()
        self.assertEqual((var.get(), changes), ("c", ["c"]))
        seg.focus_force()
        self.pump()
        for key, expected in (("<Left>", "b"), ("<Left>", "a"), ("<Left>", "a"), ("<End>", "c"), ("<Home>", "a"),
                              ("<Right>", "b"), ("<Down>", "c"), ("<Up>", "b")):
            seg.event_generate(key)
            self.pump()
            self.assertEqual(var.get(), expected, key)

    def test_segmented_control_shows_the_selection_and_follows_the_variable(self):
        frame = self.make_frame()
        var = tk.StringVar(value="a")
        seg = gw.Segmented(frame, self.style, [("a", "Alpha"), ("b", "Beta")], var)
        seg.pack()
        t = self.style.theme
        self.assertEqual(str(seg.buttons["a"].cget("bg")), t.accent)
        self.assertEqual(str(seg.buttons["b"].cget("bg")), t.field)
        var.set("b")
        self.assertEqual(str(seg.buttons["b"].cget("bg")), t.accent)
        self.assertEqual(str(seg.buttons["b"].cget("fg")), t.on_accent)

    def test_disabled_segmented_control_ignores_input(self):
        frame = self.make_frame()
        var = tk.StringVar(value="a")
        seg = gw.Segmented(frame, self.style, [("a", "Alpha"), ("b", "Beta")], var)
        seg.pack()
        seg.set_enabled(False)
        seg.buttons["b"].event_generate("<Button-1>")
        self.pump()
        self.assertEqual(var.get(), "a")
        self.assertEqual(str(seg.cget("takefocus")), "0")
        seg.set_enabled(True)
        seg.buttons["b"].event_generate("<Button-1>")
        self.pump()
        self.assertEqual(var.get(), "b")

    def test_destroyed_segmented_control_stops_listening(self):
        frame = self.make_frame()
        var = tk.StringVar(value="a")
        seg = gw.Segmented(frame, self.style, [("a", "Alpha"), ("b", "Beta")], var)
        seg.pack()
        seg.destroy()
        var.set("b")
        self.assertEqual(var.trace_info(), [])

    def test_expander_toggles(self):
        frame = self.make_frame()
        expander = gw.Expander(frame, self.style, "Show reasoning")
        expander.pack(fill=tk.X)
        tk.Label(expander.body, text="reason").pack()
        self.root.update()
        self.assertFalse(expander.body.winfo_ismapped())
        expander.header.event_generate("<Button-1>")
        self.pump()
        self.assertTrue(expander.is_open and expander.body.winfo_ismapped())
        self.assertIn("\u25be", expander.header.cget("text"))
        expander.toggle()
        self.assertIn("\u25b8", expander.header.cget("text"))

    def test_tooltip_shows_and_hides(self):
        frame = self.make_frame()
        mark = gw.help_mark(frame, self.style, "Low means no routable path.")
        mark.pack()
        self.root.update()
        self.assertEqual(mark.cget("takefocus"), 1)
        tooltip = gw.Tooltip(mark, "text", self.style, delay=10)
        tooltip._show()
        self.assertIsNotNone(tooltip.window)
        tooltip._hide()
        self.assertIsNone(tooltip.window)

    def test_priority_badge_shows_the_word(self):
        frame = self.make_frame()
        for priority in ("NOW", "NEXT", "NEVER"):
            badge = gw.priority_badge(frame, self.style, priority)
            self.assertEqual(badge.cget("text"), priority)
            self.assertEqual((badge.fill, str(badge.cget("fg"))), self.style.bucket(priority))
            self.assertEqual(str(badge.cget("bg")), self.style.theme.card)
            self.assertEqual((badge.image.width(), badge.image.height()), badge.size)

    def test_field_label_adds_a_help_mark_only_when_asked(self):
        frame = self.make_frame()
        plain = gw.field_label(frame, self.style, "Patch status")
        helped = gw.field_label(frame, self.style, "Exposure", "Explained")
        self.assertEqual(len(plain.winfo_children()), 1)
        self.assertEqual(len(helped.winfo_children()), 2)


def walk(widget):
    for child in widget.winfo_children():
        yield child
        yield from walk(child)


class ReferenceListTests(DisplayTestCase):
    REFS = (refs.Reference("BOD 26-04", "https://www.cisa.gov/bod"), refs.Reference(url="https://a.example.com/x/y"),
            refs.Reference(text="See the vendor page"), refs.Reference(text="http://old.example.com/z"))

    def make(self, **options):
        opened = []
        box = gw.ReferenceList(self.root, self.style, opened.append, **options)
        box.pack()
        self.root.deiconify()
        self.pump(0.1)
        return box, opened

    def test_links_show_their_domain_and_text_items_are_not_links(self):
        box, _opened = self.make()
        box.show(self.REFS)
        links = [w for w in walk(box) if isinstance(w, gw.LinkLabel)]
        self.assertEqual([w.cget("text") for w in links], ["BOD 26-04", "a.example.com"])
        texts = [w.cget("text") for w in walk(box) if isinstance(w, tk.Label) and not isinstance(w, gw.LinkLabel)]
        self.assertEqual(texts, ["www.cisa.gov", "/x/y", "See the vendor page", "http://old.example.com/z"])

    def test_clicking_a_link_passes_that_reference_on(self):
        box, opened = self.make()
        box.show(self.REFS)
        self.pump(0.2)
        next(w for w in walk(box) if isinstance(w, gw.LinkLabel)).event_generate("<Button-1>")
        self.pump(0.1)
        self.assertEqual(opened, [self.REFS[0]])

    def test_compact_mode_puts_the_domain_on_the_same_line_and_a_limit_says_how_many_are_left_out(self):
        box, _opened = self.make(compact=True, limit=2)
        left_out = box.show(self.REFS)
        self.assertEqual(left_out, 2)
        texts = [w.cget("text") for w in walk(box) if isinstance(w, tk.Label)]
        self.assertIn("and 2 more (see Assess or the CSV export)", texts)
        link = next(w for w in walk(box) if isinstance(w, gw.LinkLabel))
        self.assertEqual(link.pack_info()["side"], "left")

    def test_showing_again_replaces_the_old_contents(self):
        box, _opened = self.make()
        box.show(self.REFS)
        box.show(())
        self.assertEqual(list(box.winfo_children()), [])

    def test_a_long_address_is_shortened_for_display_only(self):
        box, _opened = self.make()
        box.show((refs.Reference(url="https://a.example.com/" + "p" * 200),))
        shown = [w.cget("text") for w in walk(box) if isinstance(w, tk.Label) and not isinstance(w, gw.LinkLabel)]
        self.assertTrue(shown[0].endswith("...") and len(shown[0]) == 60)


class ScrollAreaTests(DisplayTestCase):
    def make(self, rows, max_height):
        area = gw.ScrollFrame(self.root, self.style.theme.card, max_height=max_height)
        area.pack(fill=tk.X)
        for i in range(rows):
            tk.Label(area.body, text=f"row {i}", bg=self.style.theme.card).pack(anchor="w")
        self.root.deiconify()
        self.pump(0.2)
        return area

    def test_it_grows_with_its_content_up_to_the_limit_then_shows_a_scrollbar(self):
        small = self.make(2, 150)
        self.assertLess(small.canvas.winfo_reqheight(), 150)
        self.assertFalse(small.bar.winfo_ismapped())
        small.destroy()
        big = self.make(40, 150)
        self.assertEqual(big.canvas.winfo_reqheight(), 150)
        self.assertTrue(big.bar.winfo_ismapped())

    def test_mouse_wheel_scrolling_survives_the_pointer_moving_over_a_label_inside(self):
        area = self.make(40, 150)
        label = area.body.winfo_children()[0]
        area.canvas.event_generate("<Enter>")
        self.assertTrue(area.bind_all("<MouseWheel>"))
        event = mock.Mock(x_root=label.winfo_rootx() + 2, y_root=label.winfo_rooty() + 2)
        area._unbind_wheel(event)
        self.assertTrue(area.bind_all("<MouseWheel>"), "the wheel binding was dropped over a child widget")
        outside = mock.Mock(x_root=-50, y_root=-50)
        area._unbind_wheel(outside)
        self.assertFalse(area.bind_all("<MouseWheel>"))


class EntryLimitTests(DisplayTestCase):
    def make(self, **options):
        calls = []
        variable = tk.StringVar(self.root)
        frame = self.make_frame()
        entry = gw.rounded_entry(frame, self.style, variable, on_too_long=lambda: calls.append(1), **options)
        entry.pack()
        self.root.deiconify()
        self.pump(0.1)
        return entry, variable, calls

    def test_text_within_the_limit_is_accepted_and_text_beyond_it_is_refused_with_a_callback(self):
        entry, _variable, calls = self.make(max_chars=10)
        entry.insert(0, "abcde")
        entry.insert("end", "fghij")
        self.assertEqual((entry.get(), calls), ("abcdefghij", []))
        entry.insert("end", "k")
        entry.insert(0, "X")
        self.assertEqual((entry.get(), len(calls)), ("abcdefghij", 2))

    def test_a_huge_paste_is_refused_without_touching_the_widget(self):
        entry, _variable, calls = self.make()
        start = time.monotonic()
        entry.insert(0, "A" * 5_000_000)
        self.assertLess(time.monotonic() - start, 2.0)
        self.assertEqual((entry.get(), len(calls)), ("", 1))

    def test_the_default_limit_is_generous_for_real_use(self):
        entry, _variable, calls = self.make()
        entry.insert(0, "x" * gw.MAX_ENTRY_CHARS)
        self.assertEqual((len(entry.get()), calls), (gw.MAX_ENTRY_CHARS, []))

    def test_the_program_setting_the_variable_is_not_blocked_by_the_limit(self):
        entry, variable, calls = self.make(max_chars=10)
        variable.set("a longer text than ten characters")
        self.pump(0.1)
        self.assertEqual((entry.get(), calls), ("a longer text than ten characters", []))
        entry.insert("end", "!")  # typing more on top of it is refused
        self.assertEqual(len(calls), 1)


class LinkLabelTests(DisplayTestCase):
    def make(self, calls):
        link = gw.LinkLabel(self.root, self.style, "Advisory", lambda: calls.append(1))
        link.pack()
        self.root.deiconify()
        self.pump(0.1)
        return link

    def test_a_click_runs_the_command_once(self):
        calls = []
        link = self.make(calls)
        link.event_generate("<Button-1>")
        self.pump(0.1)
        self.assertEqual(calls, [1])

    def test_it_looks_like_a_link_and_shows_hover_and_focus(self):
        link = self.make([])
        self.assertEqual(str(link.cget("cursor")), "hand2")
        self.assertEqual(str(link.cget("fg")), self.style.theme.accent)
        self.assertEqual(str(link.cget("takefocus")), "1")
        plain = str(link.cget("font"))
        link.event_generate("<Enter>")
        self.assertIn("underline", str(link.cget("font")))
        link.event_generate("<Leave>")
        self.assertEqual(str(link.cget("font")), plain)


class RoundedLookTests(DisplayTestCase):
    def test_cards_hide_their_square_corners_with_the_card_colour_inside(self):
        frame = self.make_frame()
        inner = gw.card(frame, self.style, "Vulnerability")
        outer = inner.master
        self.root.update()
        self.assertEqual(len(outer.corner_labels), 4)
        t = self.style.theme
        top_left = outer.corner_labels[0].image
        self.assertEqual(top_left.get(0, 0), tuple(int(frame.cget("bg")[i:i + 2], 16) for i in (1, 3, 5)))
        radius = top_left.width()
        inside = top_left.get(radius - 1, radius - 1)
        self.assertEqual(inside, tuple(int(t.card[i:i + 2], 16) for i in (1, 3, 5)))
        self.assertEqual(top_left.get(radius - 1, 0), tuple(int(t.border[i:i + 2], 16) for i in (1, 3, 5)))

    def test_a_card_never_draws_a_black_focus_border_when_a_child_has_focus(self):
        frame = self.make_frame()
        inner = gw.card(frame, self.style, "Vulnerability")
        outer = inner.master
        self.assertEqual(str(outer.cget("highlightcolor")), self.style.theme.border)
        self.assertEqual(str(outer.cget("highlightbackground")), self.style.theme.border)
        self.assertNotIn(str(outer.cget("highlightcolor")).lower(), ("#000000", "black"))

    def test_empty_message_lines_take_almost_no_space(self):
        frame = self.make_frame()
        message = gw.MessageLabel(frame, self.style)
        message.pack(fill=tk.X)
        self.root.update()
        empty_height = message.winfo_reqheight()
        self.assertLessEqual(empty_height, 4)
        message.configure(text="Something to say", fg=self.style.theme.error)
        self.root.update()
        self.assertGreater(message.winfo_reqheight(), 12)
        self.assertEqual((message.cget("text"), str(message.cget("fg"))), ("Something to say", self.style.theme.error))
        message.config(text="")
        self.root.update()
        self.assertEqual(message.winfo_reqheight(), empty_height)

    def test_chips_are_pills(self):
        frame = self.make_frame()
        chip = gw.chip(frame, self.style, "In CISA KEV", "raise")
        self.assertEqual(chip.shape["radius"], chip.image.height() // 2)
        self.assertEqual(chip.shape["fill"], None)
        self.assertEqual(chip.shape["ring"], self.style.theme.raise_)

    def test_segmented_corners_follow_the_selected_segments_and_the_focus_ring(self):
        frame = self.make_frame()
        var = tk.StringVar(value="a")
        seg = gw.Segmented(frame, self.style, [("a", "Alpha"), ("b", "Beta"), ("c", "Gamma")], var)
        seg.pack()
        self.root.update()
        t = self.style.theme
        rgb = lambda colour: tuple(int(colour[i:i + 2], 16) for i in (1, 3, 5))  # noqa: E731
        tl, tr = seg.corner_labels[0].image, seg.corner_labels[1].image
        radius = tl.width()
        self.assertEqual(tl.get(radius - 1, radius - 1), rgb(t.accent))
        self.assertEqual(tr.get(0, radius - 1), rgb(t.field))
        var.set("c")
        self.root.update()
        self.assertEqual(seg.corner_labels[0].image.get(radius - 1, radius - 1), rgb(t.field))
        self.assertEqual(seg.corner_labels[1].image.get(0, radius - 1), rgb(t.accent))
        seg._ring(t.accent)
        self.assertEqual(seg.corner_labels[0].image.get(radius - 1, 0), rgb(t.accent))
        seg._ring(t.border)
        self.assertEqual(seg.corner_labels[0].image.get(radius - 1, 0), rgb(t.border))

    def test_rounded_inputs_recolour_their_corners_for_focus_and_errors(self):
        frame = self.make_frame()
        entry = gw.rounded_entry(frame, self.style, width=10)
        entry.pack(ipady=4)
        self.root.update()
        t = self.style.theme
        rgb = lambda colour: tuple(int(colour[i:i + 2], 16) for i in (1, 3, 5))  # noqa: E731
        radius = entry.corner_labels[0].image.width()
        self.assertEqual(len(entry.corner_labels), 4)
        self.assertEqual(entry.corner_labels[0].image.get(radius - 1, 0), rgb(t.border))
        entry.focused = True
        entry.repaint()
        self.assertEqual(entry.corner_labels[0].image.get(radius - 1, 0), rgb(t.accent))
        entry.configure(highlightbackground=t.error, highlightcolor=t.error)
        entry.repaint()
        self.assertEqual(entry.corner_labels[0].image.get(radius - 1, 0), rgb(t.error))
        entry.focused = False
        entry.configure(highlightbackground=t.border, highlightcolor=t.accent)
        entry.repaint()
        self.assertEqual(entry.corner_labels[0].image.get(radius - 1, 0), rgb(t.border))

    def test_rounded_inputs_follow_real_keyboard_focus(self):
        frame = self.make_frame()
        entry = gw.rounded_entry(frame, self.style, width=10)
        entry.pack()
        self.root.update()
        entry.focus_force()
        self.pump(0.1)
        if not entry.focused:
            self.skipTest("the window manager did not give the test window keyboard focus")
        self.assertEqual(entry.corner_labels[0].image.get(entry.corner_labels[0].image.width() - 1, 0),
                         tuple(int(self.style.theme.accent[i:i + 2], 16) for i in (1, 3, 5)))

    def test_buttons_show_a_pressed_state_while_the_mouse_is_down(self):
        frame = self.make_frame()
        b = gw.button(frame, self.style, "Save", lambda: None)
        b.pack()
        self.root.update()
        normal = str(b.cget("image"))
        b.event_generate("<ButtonPress-1>")
        pressed = str(b.cget("image"))
        self.assertNotEqual(pressed, normal)
        b.event_generate("<ButtonRelease-1>")
        # Back to the resting look, or the hover look if the real pointer happens to be over the button
        self.assertNotEqual(str(b.cget("image")), pressed)

    def test_a_disabled_button_does_not_show_the_pressed_state(self):
        frame = self.make_frame()
        b = gw.button(frame, self.style, "Save", lambda: None)
        b.pack()
        gw.set_enabled(b, False)
        shown = str(b.cget("image"))
        b.event_generate("<ButtonPress-1>")
        self.assertEqual(str(b.cget("image")), shown)

    def test_bordered_frames_in_every_view_use_their_border_colour_for_focus(self):
        import tempfile
        from pathlib import Path

        import gui_batch
        import gui_threat
        from gui_context import Context
        from settings import DEFAULT_SETTINGS
        from uiprefs import DEFAULT_PREFS
        with tempfile.TemporaryDirectory() as tmp:
            ctx = Context(self.root, self.style, DEFAULT_SETTINGS, DEFAULT_PREFS)
            ctx.data_dir = Path(tmp) / "data"
            holder = tk.Toplevel(self.root)
            self.addCleanup(holder.destroy)
            checked = 0
            for view in (gui_batch.BatchView(ctx, holder), gui_threat.ThreatView(ctx, holder)):
                stack = [view.frame]
                while stack:
                    node = stack.pop()
                    stack.extend(node.winfo_children())
                    if type(node) is tk.Frame and int(node.cget("highlightthickness")) == 1:
                        checked += 1
                        self.assertEqual(str(node.cget("highlightcolor")), str(node.cget("highlightbackground")))
            self.assertGreaterEqual(checked, 3)


class ScrollFrameTests(DisplayTestCase):
    def build(self, rows):
        frame = self.make_frame(width=300, height=200)
        scroll = gw.ScrollFrame(frame, self.style.theme.card)
        scroll.pack(fill=tk.BOTH, expand=True)
        for i in range(rows):
            tk.Label(scroll.body, text=f"row {i}", pady=8).pack()
        self.pump(0.2)
        return scroll

    def test_the_scrollbar_appears_only_when_the_content_does_not_fit(self):
        short = self.build(2)
        self.assertFalse(short.bar.winfo_ismapped())
        tall = self.build(40)
        self.assertTrue(tall.bar.winfo_ismapped())

    def test_the_scrollbar_follows_the_content_size(self):
        scroll = self.build(40)
        for child in scroll.body.winfo_children()[2:]:
            child.destroy()
        self.pump(0.2)
        self.assertFalse(scroll.bar.winfo_ismapped())

    def test_scrolling_moves_the_view_and_returns_to_the_top(self):
        scroll = self.build(40)
        scroll.canvas.yview_scroll(5, "units")
        self.pump()
        self.assertGreater(scroll.canvas.yview()[0], 0)
        scroll.scroll_to_top()
        self.assertEqual(scroll.canvas.yview()[0], 0)

    def test_the_body_follows_the_window_width(self):
        scroll = self.build(2)
        self.assertEqual(scroll.canvas.itemcget(scroll._window, "width"), str(scroll.canvas.winfo_width()))


class WorkerTests(DisplayTestCase):
    def run_job(self, job, **kwargs):
        worker = gw.Worker(self.root, interval_ms=10)
        done, progress = [], []
        worker.start(job, lambda *a: done.append(a), progress.append, **kwargs)
        self.assertTrue(self.pump(5, until=lambda: bool(done)))
        return worker, done[0], progress

    def test_result_comes_back_on_the_tk_thread(self):
        seen = []
        worker = gw.Worker(self.root, interval_ms=10)
        main = threading.current_thread()
        done = []
        worker.start(lambda cancel, report: (report("working"), 42)[1],
                     lambda r, e: (seen.append(threading.current_thread() is main), done.append((r, e))),
                     lambda m: seen.append(m))
        self.pump(5, until=lambda: bool(done))
        self.assertEqual(done, [(42, "")])
        self.assertEqual(seen[0], "working")
        self.assertTrue(seen[-1])

    def test_errors_become_short_messages_not_tracebacks(self):
        def failing(cancel, report):
            raise RuntimeError("the connection timed out " + "x" * 1000)
        _worker, (result, error), _progress = self.run_job(failing)
        self.assertIsNone(result)
        self.assertTrue(error.startswith("the connection timed out"))
        self.assertLessEqual(len(error), 300)
        self.assertNotIn("Traceback", error)
        _w, (_r, empty_error), _p = self.run_job(lambda c, r: (_ for _ in ()).throw(KeyError()))
        self.assertEqual(empty_error, "KeyError")

    def test_only_one_job_runs_at_a_time_and_cancel_is_visible_to_the_job(self):
        started, release = threading.Event(), threading.Event()

        def slow(cancel, report):
            started.set()
            cancel.wait(5)
            return "cancelled" if cancel.is_set() else "timeout"

        worker = gw.Worker(self.root, interval_ms=10)
        done = []
        self.assertTrue(worker.start(slow, lambda r, e: done.append(r)))
        self.assertTrue(started.wait(2))
        self.assertTrue(worker.running)
        self.assertFalse(worker.start(lambda c, r: 1, lambda r, e: None))
        worker.cancel()
        self.pump(5, until=lambda: bool(done))
        self.assertEqual(done, ["cancelled"])
        self.assertFalse(release.is_set())
        self.pump(0.3)
        self.assertFalse(worker.running)
        self.assertTrue(worker.start(lambda c, r: "again", lambda r, e: done.append(r)))
        self.pump(5, until=lambda: done[-1] == "again")


class AskTextTests(DisplayTestCase):
    def setUp(self):
        self.root.deiconify()
        self.root.geometry("300x200+0+0")
        self.root.update()
        self.addCleanup(self.root.withdraw)

    def drive(self, action):
        def run():
            dialog = next(w for w in self.root.winfo_children() if isinstance(w, tk.Toplevel))
            self.root.update()
            entry = next(w for w in dialog.winfo_children() if isinstance(w, tk.Entry))
            entry.focus_force()
            self.root.update()
            action(dialog, entry)
        self.root.after(150, run)

    def test_accepts_a_reason(self):
        def act(dialog, entry):
            entry.insert(0, "  Patched by vendor hotfix  ")
            entry.event_generate("<Return>")
        self.drive(act)
        self.assertEqual(gw.ask_text(self.root, self.style, "Override", "Why?"), "Patched by vendor hotfix")

    def flaky_grab(self, failures):
        """Make Toplevel.grab_set fail like a window that is not yet viewable, the given number of times."""
        real, calls = tk.Toplevel.grab_set, {"n": 0}

        def grab_set(window):
            calls["n"] += 1
            if calls["n"] <= failures:
                raise tk.TclError("grab failed: window not viewable")
            return real(window)

        patcher = mock.patch.object(tk.Toplevel, "grab_set", grab_set)
        patcher.start()
        self.addCleanup(patcher.stop)
        return calls

    def test_a_dialog_that_is_not_yet_viewable_is_retried_and_still_works(self):
        calls = self.flaky_grab(failures=4)

        def act(dialog, entry):
            def answer_once_retries_are_done():
                if calls["n"] <= 4:
                    dialog.after(20, answer_once_retries_are_done)
                    return
                entry.insert(0, "Compensating control verified")
                entry.event_generate("<Return>")
            answer_once_retries_are_done()
        self.drive(act)
        self.assertEqual(gw.ask_text(self.root, self.style, "Override", "Why?"), "Compensating control verified")
        self.assertGreater(calls["n"], 4)

    def test_a_dialog_that_can_never_grab_still_works_and_never_raises(self):
        calls = self.flaky_grab(failures=10 ** 6)

        def act(dialog, entry):
            entry.insert(0, "Reason given")
            entry.event_generate("<Return>")
        self.drive(act)
        self.assertEqual(gw.ask_text(self.root, self.style, "Override", "Why?"), "Reason given")
        self.pump(0.3)
        self.assertGreaterEqual(calls["n"], 1)
        self.assertLessEqual(calls["n"], gw.GRAB_RETRIES + 1)

    def test_retries_stop_once_the_dialog_is_gone(self):
        calls = self.flaky_grab(failures=10 ** 6)
        window = tk.Toplevel(self.root)
        gw.grab_when_visible(window)
        window.destroy()
        count = calls["n"]
        self.pump(0.2)
        self.assertEqual(calls["n"], count)

    def test_empty_reason_is_refused_then_cancel_returns_none(self):
        labels = []

        def act(dialog, entry):
            entry.event_generate("<Return>")
            self.root.update()
            labels.extend(w.cget("text") for w in dialog.winfo_children() if isinstance(w, tk.Label))
            entry.event_generate("<Escape>")
        self.drive(act)
        self.assertIsNone(gw.ask_text(self.root, self.style, "Override", "Why?"))
        self.assertIn("A reason is required.", labels)


if __name__ == "__main__":
    unittest.main()
