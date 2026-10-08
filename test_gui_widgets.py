import threading
import tkinter as tk
import unittest

import gui_widgets as gw
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
            enabled_look = (str(b.cget("bg")), str(b.cget("fg")))
            gw.set_enabled(b, False)
            self.assertEqual(str(b.cget("state")), "disabled")
            self.assertEqual((str(b.cget("bg")), str(b.cget("fg"))), (self.style.theme.border, self.style.theme.muted))
            self.assertNotEqual((str(b.cget("bg")), str(b.cget("fg"))), enabled_look)
            b.invoke()
            gw.set_enabled(b, True)
            self.assertEqual((str(b.cget("bg")), str(b.cget("fg")), str(b.cget("state"))), (*enabled_look, "normal"))
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
            self.assertEqual((str(badge.cget("bg")), str(badge.cget("fg"))), self.style.bucket(priority))

    def test_field_label_adds_a_help_mark_only_when_asked(self):
        frame = self.make_frame()
        plain = gw.field_label(frame, self.style, "Patch status")
        helped = gw.field_label(frame, self.style, "Exposure", "Explained")
        self.assertEqual(len(plain.winfo_children()), 1)
        self.assertEqual(len(helped.winfo_children()), 2)


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
