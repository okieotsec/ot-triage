"""Reusable Tk widgets: cards, buttons, segmented controls, chips, tooltips, expanders, background work."""
import queue
import threading
import tkinter as tk
from tkinter import ttk

from gui_round import photo, recolor_corners, round_corners, shape_label, text_size
from gui_theme import SYMBOLS

CARD_RADIUS, BUTTON_RADIUS, SEGMENT_RADIUS, BADGE_RADIUS, ENTRY_RADIUS = 12, 9, 9, 14, 9


def card(parent, style, title, expand=False, pady=(0, 16)):
    """Create a titled, rounded card and return the frame to put its content in."""
    t = style.theme
    outer = tk.Frame(parent, bg=t.card, highlightthickness=1, highlightbackground=t.border, highlightcolor=t.border)
    outer.pack(fill=tk.BOTH if expand else tk.X, expand=expand, pady=pady)
    if title:
        tk.Label(outer, text=title.upper(), font=style.font(9, "bold"), bg=t.card, fg=t.accent).pack(
            anchor="w", padx=20, pady=(14, 4))
    inner = tk.Frame(outer, bg=t.card)
    inner.pack(fill=tk.BOTH, expand=expand, padx=20, pady=(0 if title else 14, 16))
    round_corners(outer, CARD_RADIUS, t.border, parent.cget("bg"), fill=t.card)
    return inner


class MessageLabel(tk.Label):
    """A one-line message that takes almost no space while it is empty."""

    def __init__(self, parent, style, **options):
        self._normal, self._tiny = style.font(9), (style.family, 1)
        options.setdefault("bg", style.theme.card)
        options.setdefault("fg", style.theme.muted)
        super().__init__(parent, text="", font=self._tiny, anchor="w", justify="left", pady=0, bd=0,
                         highlightthickness=0, **options)

    def configure(self, cnf=None, **options):
        """Configure the label; setting text also switches between the normal and the collapsed size."""
        if "text" in options:
            options["font"] = self._normal if options["text"] else self._tiny
            options["pady"] = 2 if options["text"] else 0
        return super().configure(cnf, **options)

    config = configure


def rounded_entry(parent, style, variable=None, width=20, size=11, bold=False, justify="left", outside=None):
    """Create a text input with rounded corners; call .repaint() after changing its highlight colours."""
    t = style.theme
    outside = outside or parent.cget("bg")
    entry = tk.Entry(parent, textvariable=variable, width=width, font=style.font(size, "bold" if bold else "normal"),
                     bg=t.field, fg=t.text, insertbackground=t.text, relief="flat", justify=justify,
                     highlightthickness=2, highlightbackground=t.border, highlightcolor=t.accent,
                     selectbackground=t.accent, selectforeground=t.on_accent)
    round_corners(entry, ENTRY_RADIUS, t.border, outside, ring_width=2, fill=t.field)
    entry.focused = False

    def repaint():
        ring = entry.cget("highlightcolor") if entry.focused else entry.cget("highlightbackground")
        recolor_corners(entry, ENTRY_RADIUS, str(ring), outside, ring_width=2, fill=t.field)

    def focus(state):
        entry.focused = state
        repaint()

    entry.repaint = repaint
    entry.bind("<FocusIn>", lambda _e: focus(True), add="+")
    entry.bind("<FocusOut>", lambda _e: focus(False), add="+")
    return entry


def field_label(parent, style, text, help_text=None, bg=None):
    """Create a small caption above an input, with an optional help mark."""
    bg = bg or style.theme.card
    row = tk.Frame(parent, bg=bg)
    row.pack(fill=tk.X, pady=(11, 4))
    tk.Label(row, text=text, font=style.font(9), bg=bg, fg=style.theme.muted).pack(side=tk.LEFT)
    if help_text:
        help_mark(row, style, help_text, bg).pack(side=tk.LEFT, padx=(6, 0))
    return row


def _shade(color, toward, amount):
    """Blend a #rrggbb colour towards another by a fraction."""
    mixed = [round(int(color[i:i + 2], 16) * (1 - amount) + int(toward[i:i + 2], 16) * amount) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(mixed)


def button(parent, style, text, command, kind="primary", **options):
    """Create a rounded button; kind is primary or secondary. Use set_enabled to enable or disable it."""
    t = style.theme
    outside = parent.cget("bg")
    fill, fg = (t.accent, t.on_accent) if kind == "primary" else (t.field, t.text)
    ring = None if kind == "primary" else t.border
    font = style.font(10, "bold" if kind == "primary" else "normal")
    text_w, text_h = text_size(parent, font, text)
    width, height = text_w + 40, text_h + 20
    images = {"normal": photo(parent, width, height, BUTTON_RADIUS, fill, ring),
              "pressed": photo(parent, width, height, BUTTON_RADIUS, _shade(fill, t.text, 0.18), ring),
              "disabled": photo(parent, width, height, BUTTON_RADIUS, t.border)}
    widget = tk.Button(parent, text=text, command=command, font=font, image=images["normal"], compound="center",
                       fg=fg, bg=outside, activebackground=outside, activeforeground=fg, relief="flat", bd=0,
                       padx=0, pady=0, cursor="hand2", highlightthickness=2, highlightbackground=outside,
                       highlightcolor=t.accent, disabledforeground=t.muted, **options)
    widget.images, widget.fill = images, fill
    widget.look = {"normal": (fill, fg, "hand2", images["normal"]), "disabled": (t.border, t.muted, "arrow",
                                                                                  images["disabled"])}
    widget.bind("<ButtonPress-1>", lambda _e: widget.cget("state") == "normal" and widget.configure(
        image=images["pressed"]), add="+")
    widget.bind("<ButtonRelease-1>", lambda _e: widget.cget("state") == "normal" and widget.configure(
        image=images["normal"]), add="+")
    return widget


def set_enabled(widget, enabled):
    """Enable or disable a button made by button(), with a clearly different look when disabled."""
    fill, fg, cursor, image = widget.look["normal" if enabled else "disabled"]
    widget.fill = fill
    widget.configure(state="normal" if enabled else "disabled", fg=fg, cursor=cursor, image=image)


class ScrollFrame(tk.Frame):
    """A vertically scrollable area; put content in .body."""

    def __init__(self, parent, bg):
        super().__init__(parent, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.bar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.bar.set)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.body = tk.Frame(self.canvas, bg=bg)
        self._window = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.body.bind("<Configure>", self._on_body_resize)
        self.canvas.bind("<Configure>", self._on_canvas_resize)
        for widget in (self.canvas, self.body):
            widget.bind("<Enter>", self._bind_wheel)
            widget.bind("<Leave>", self._unbind_wheel)

    def _on_body_resize(self, _event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self._toggle_bar()

    def _on_canvas_resize(self, event):
        self.canvas.itemconfigure(self._window, width=event.width)
        self._toggle_bar()

    def _toggle_bar(self):
        """Show the scrollbar only when the content is taller than the visible area."""
        needed = self.body.winfo_reqheight() > self.canvas.winfo_height() > 1
        if needed and not self.bar.winfo_ismapped():
            self.bar.pack(side=tk.RIGHT, fill=tk.Y, before=self.canvas)
        elif not needed and self.bar.winfo_ismapped():
            self.bar.pack_forget()

    def _bind_wheel(self, _event):
        self.bind_all("<MouseWheel>", self._wheel)
        self.bind_all("<Button-4>", self._wheel)
        self.bind_all("<Button-5>", self._wheel)

    def _unbind_wheel(self, _event):
        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.unbind_all(sequence)

    def _wheel(self, event):
        if self.body.winfo_reqheight() <= self.canvas.winfo_height():
            return
        step = -1 if event.num == 4 or getattr(event, "delta", 0) > 0 else 1
        self.canvas.yview_scroll(step * 3, "units")

    def scroll_to_top(self):
        """Scroll back to the top."""
        self.canvas.yview_moveto(0)


class Tooltip:
    """A small text popup shown on hover or keyboard focus."""

    def __init__(self, widget, text, style, delay=350):
        self.widget, self.text, self.style, self.delay = widget, text, style, delay
        self.window, self.job = None, None
        for sequence in ("<Enter>", "<FocusIn>"):
            widget.bind(sequence, self._schedule, add="+")
        for sequence in ("<Leave>", "<FocusOut>", "<Escape>", "<ButtonPress>"):
            widget.bind(sequence, self._hide, add="+")

    def _schedule(self, _event=None):
        self._hide()
        self.job = self.widget.after(self.delay, self._show)

    def _show(self):
        if self.window or not self.widget.winfo_exists():
            return
        t = self.style.theme
        self.window = tk.Toplevel(self.widget)
        self.window.wm_overrideredirect(True)
        x = self.widget.winfo_rootx() + 18
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.window.wm_geometry(f"+{x}+{y}")
        tk.Label(self.window, text=self.text, justify="left", wraplength=int(300 * self.style.scale),
                 font=self.style.font(9), bg=t.header, fg=t.text, relief="solid", bd=1, padx=10, pady=8).pack()

    def _hide(self, _event=None):
        if self.job:
            self.widget.after_cancel(self.job)
            self.job = None
        if self.window:
            self.window.destroy()
            self.window = None


def help_mark(parent, style, text, bg=None):
    """Create a keyboard-focusable ? mark that explains an input."""
    t = style.theme
    mark = tk.Label(parent, text="?", font=style.font(8, "bold"), bg=bg or t.card, fg=t.muted, width=2,
                    highlightthickness=1, highlightbackground=t.muted, highlightcolor=t.accent, takefocus=1,
                    cursor="question_arrow")
    Tooltip(mark, text, style)
    return mark


def chip(parent, style, text, direction="neutral", bg=None):
    """Create a pill-shaped status chip with a symbol and a word."""
    color = style.direction(direction)
    symbol = SYMBOLS.get(direction, "")
    return shape_label(parent, f"{symbol} {text}".strip(), style.font(9), color, ring=color,
                       outside=bg or style.theme.card, padx=11, pady=3)


class FlowFrame(tk.Frame):
    """A frame that lays its children out left to right and wraps them onto new rows."""

    def __init__(self, parent, bg, gap=8):
        super().__init__(parent, bg=bg, height=1)
        self.gap, self.items = gap, []
        self.bind("<Configure>", lambda _e: self.relayout())

    def set_items(self, widgets):
        """Replace the contents with the given widgets (already created with this frame as parent)."""
        for old in self.items:
            old.destroy()
        self.items = list(widgets)
        self.relayout()

    def relayout(self):
        """Position the children, wrapping to the current width."""
        width = max(self.winfo_width(), 1)
        x = y = row_height = 0
        for item in self.items:
            w, h = item.winfo_reqwidth(), item.winfo_reqheight()
            if x and x + w > width:
                x, y, row_height = 0, y + row_height + self.gap, 0
            item.place(x=x, y=y)
            x += w + self.gap
            row_height = max(row_height, h)
        total = y + row_height
        if self.items and int(self.cget("height")) != total:
            self.configure(height=total)


class Segmented(tk.Frame):
    """A row of mutually exclusive choices, operated by mouse or the arrow keys."""

    def __init__(self, parent, style, options, variable, command=None, bg=None):
        t = style.theme
        super().__init__(parent, bg=t.border, highlightthickness=2, highlightbackground=t.border,
                         highlightcolor=t.accent, takefocus=1, bd=0)
        self.style, self.options, self.variable, self.command = style, list(options), variable, command
        self.outside = bg or parent.cget("bg")
        self.ring_color = t.border
        self.buttons, self.enabled = {}, True
        for index, (value, text) in enumerate(self.options):
            label = tk.Label(self, text=text, font=style.font(10), padx=6, pady=8, cursor="hand2")
            label.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 1, 0))
            label.bind("<Button-1>", lambda _e, v=value: self._choose(v, focus=True))
            self.buttons[value] = label
            self.columnconfigure(index, weight=1, uniform="seg")
        round_corners(self, SEGMENT_RADIUS, self.ring_color, self.outside, ring_width=2, fill=t.field)
        self.bind("<FocusIn>", lambda _e: self._ring(t.accent), add="+")
        self.bind("<FocusOut>", lambda _e: self._ring(t.border), add="+")
        for key, step in (("<Left>", -1), ("<Up>", -1), ("<Right>", 1), ("<Down>", 1)):
            self.bind(key, lambda _e, s=step: self._step(s))
        self.bind("<Home>", lambda _e: self._choose(self.options[0][0]))
        self.bind("<End>", lambda _e: self._choose(self.options[-1][0]))
        self._trace = variable.trace_add("write", lambda *_a: self.refresh())
        self.bind("<Destroy>", self._on_destroy)
        self.refresh()

    def _ring(self, color):
        self.ring_color = color
        self._paint_corners()

    def _paint_corners(self):
        first, last = self.buttons[self.options[0][0]], self.buttons[self.options[-1][0]]
        left, right = str(first.cget("bg")), str(last.cget("bg"))
        recolor_corners(self, SEGMENT_RADIUS, self.ring_color, self.outside, ring_width=2,
                        fill={"tl": left, "bl": left, "tr": right, "br": right})

    def _on_destroy(self, event):
        if event.widget is self:
            try:
                self.variable.trace_remove("write", self._trace)
            except tk.TclError:
                pass

    def _choose(self, value, focus=False):
        if not self.enabled:
            return
        if focus:
            self.focus_set()
        if self.variable.get() != value:
            self.variable.set(value)
            if self.command:
                self.command()

    def _step(self, step):
        values = [v for v, _t in self.options]
        current = values.index(self.variable.get()) if self.variable.get() in values else 0
        self._choose(values[max(0, min(len(values) - 1, current + step))])

    def set_enabled(self, enabled):
        """Enable or disable the control."""
        self.enabled = enabled
        self.configure(takefocus=1 if enabled else 0)
        self.refresh()

    def refresh(self):
        """Redraw the selected state."""
        t, selected = self.style.theme, self.variable.get()
        for value, label in self.buttons.items():
            on = value == selected
            fg = (t.on_accent if on else t.muted) if self.enabled else t.muted
            label.configure(bg=t.accent if on and self.enabled else (t.border if on else t.field), fg=fg,
                            font=self.style.font(10, "bold" if on else "normal"))
        self._paint_corners()


class Expander(tk.Frame):
    """A header that shows or hides a body frame."""

    def __init__(self, parent, style, title, bg=None, open_=False):
        t = style.theme
        super().__init__(parent, bg=bg or t.card)
        self.style, self.title, self.is_open = style, title, open_
        self.header = tk.Label(self, font=style.font(10), bg=bg or t.card, fg=t.accent, cursor="hand2", anchor="w",
                               takefocus=1, highlightthickness=1, highlightbackground=bg or t.card,
                               highlightcolor=t.accent)
        self.header.pack(fill=tk.X)
        self.body = tk.Frame(self, bg=bg or t.card)
        for sequence in ("<Button-1>", "<Return>", "<space>"):
            self.header.bind(sequence, lambda _e: self.toggle())
        self._render()

    def toggle(self):
        """Open or close the body."""
        self.is_open = not self.is_open
        self._render()

    def _render(self):
        self.header.configure(text=f"{'▾' if self.is_open else '▸'} {self.title}")
        if self.is_open:
            self.body.pack(fill=tk.X, pady=(6, 0))
        else:
            self.body.pack_forget()


class LinkLabel(tk.Label):
    """Text that acts as a link: it opens on click, or on Enter or Space when focused, and shows its focus."""

    def __init__(self, parent, style, text, command):
        t = style.theme
        self._font = style.font(10)
        self._underlined = (*self._font[:2], "underline")
        super().__init__(parent, text=text, font=self._font, fg=t.accent, bg=t.card, cursor="hand2", anchor="w",
                         justify="left", takefocus=True, highlightthickness=1, highlightbackground=t.card,
                         highlightcolor=t.accent, bd=0, padx=0, pady=0)
        self.command = command
        for sequence in ("<Button-1>", "<Return>", "<space>", "<KP_Enter>"):
            self.bind(sequence, self._activate)
        for sequence in ("<Enter>", "<FocusIn>"):
            self.bind(sequence, lambda _e: self.configure(font=self._underlined))
        for sequence in ("<Leave>", "<FocusOut>"):
            self.bind(sequence, lambda _e: self.configure(font=self._font))

    def _activate(self, _event=None):
        self.focus_set()
        self.command()
        return "break"


class PriorityBadge(tk.Label):
    """The large rounded NOW, NEXT or NEVER badge; call show() to change what it displays."""

    def __init__(self, parent, style):
        font = style.font(30, "bold")
        text_w, text_h = text_size(parent, font, "NEVER")
        self.size = (text_w + 64, text_h + 28)
        super().__init__(parent, font=font, bg=parent.cget("bg"), compound="center", bd=0, highlightthickness=0,
                         padx=0, pady=0)
        self.fill = parent.cget("bg")

    def show(self, text, fill, fg, ring=None):
        """Display text on a rounded background of the given colour."""
        self.fill = fill
        self.image = photo(self, *self.size, BADGE_RADIUS, fill, ring)
        self.configure(text=text, fg=fg, image=self.image)


def priority_badge(parent, style, priority):
    """Create the large NOW, NEXT or NEVER badge, showing the word."""
    badge = PriorityBadge(parent, style)
    bg, fg = style.bucket(priority)
    badge.show(priority, bg, fg)
    return badge


class Worker:
    """Runs one background job and hands its result back on the Tk thread."""

    def __init__(self, root, interval_ms=100):
        self.root, self.interval = root, interval_ms
        self.events, self.thread = queue.Queue(), None
        self.cancel_event = threading.Event()
        self._on_done = self._on_progress = None

    @property
    def running(self):
        """True while a job is in progress."""
        return self.thread is not None and self.thread.is_alive()

    def start(self, job, on_done, on_progress=None):
        """Run job(cancel_event, report) in a thread; on_done(result, error_message) runs on the Tk thread."""
        if self.running:
            return False
        self.cancel_event = threading.Event()
        self._on_done, self._on_progress = on_done, on_progress
        self.events = queue.Queue()
        self.thread = threading.Thread(target=self._run, args=(job, self.events, self.cancel_event), daemon=True)
        self.thread.start()
        self.root.after(self.interval, self._poll)
        return True

    def cancel(self):
        """Ask the running job to stop at its next check."""
        self.cancel_event.set()

    @staticmethod
    def _run(job, events, cancel_event):
        try:
            result = job(cancel_event, lambda message: events.put(("progress", message)))
            events.put(("done", (result, "")))
        except Exception as error:  # noqa: BLE001  # report any failure as a message, never a traceback
            text = str(error) or type(error).__name__
            events.put(("done", (None, text[:300])))

    def _poll(self):
        finished = False
        while True:
            try:
                kind, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "progress" and self._on_progress:
                self._on_progress(payload)
            elif kind == "done":
                finished = True
                self._on_done(*payload)
        if not finished:
            self.root.after(self.interval, self._poll)


GRAB_RETRIES, GRAB_RETRY_MS = 100, 20


def grab_when_visible(window, retries=GRAB_RETRIES):
    """Make a dialog modal once the window manager has shown it; a failed grab is retried, never raised."""
    try:
        window.grab_set()
    except tk.TclError:
        if retries > 0 and window.winfo_exists():
            window.after(GRAB_RETRY_MS, lambda: grab_when_visible(window, retries - 1))


def ask_text(parent, style, title, prompt, ok_text="OK"):
    """Show a modal dialog asking for a line of text; return the text, or None if cancelled."""
    t = style.theme
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.configure(bg=t.card)
    dialog.transient(parent.winfo_toplevel())
    dialog.resizable(False, False)
    result = {"value": None}
    tk.Label(dialog, text=prompt, font=style.font(10), bg=t.card, fg=t.text, wraplength=int(380 * style.scale),
             justify="left").pack(padx=18, pady=(16, 8))
    entry = rounded_entry(dialog, style, width=44, outside=t.card)
    entry.pack(padx=18, ipady=5)
    entry.focus_set()
    error = tk.Label(dialog, text="", font=style.font(9), bg=t.card, fg=t.error)
    error.pack(anchor="w", padx=18, pady=(4, 0))

    def accept(_event=None):
        text = entry.get().strip()
        if not text:
            error.configure(text="A reason is required.")
            return
        result["value"] = text
        dialog.destroy()

    buttons = tk.Frame(dialog, bg=t.card)
    buttons.pack(fill=tk.X, padx=18, pady=14)
    button(buttons, style, ok_text, accept).pack(side=tk.RIGHT)
    button(buttons, style, "Cancel", dialog.destroy, "secondary").pack(side=tk.RIGHT, padx=(0, 8))
    dialog.bind("<Return>", accept)
    dialog.bind("<Escape>", lambda _e: dialog.destroy())
    dialog.lift()
    dialog.focus_force()
    grab_when_visible(dialog)
    parent.wait_window(dialog)
    return result["value"]
