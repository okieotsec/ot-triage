"""State and services shared by all GUI views: settings, preferences, threat data, dialogs, background work."""
from tkinter import filedialog, messagebox

import threatdata
from gui_widgets import Worker


class Context:
    """Everything a view needs from the application, so views can be tested without the window shell."""

    def __init__(self, root, style, settings, prefs, shell=None):
        self.root, self.style, self.settings, self.prefs, self.shell = root, style, settings, prefs, shell
        self.worker = Worker(root)
        self.threat_data = None
        self.assess_state = None
        self.batch_state = None
        self.updater = None
        self.data_dir = None

    # ---- threat data ----
    def get_threat_data(self):
        """Return the stored threat data, loading it on first use and warning about unusable files."""
        if self.threat_data is None:
            self.threat_data = threatdata.ThreatData.load(self.data_dir)
            if self.threat_data.warnings:
                self.warn("Threat data", "\n\n".join(self.threat_data.warnings))
        return self.threat_data

    def reload_threat_data(self):
        """Forget the loaded data so the next use reads the files again, and refresh the status bar."""
        self.threat_data = None
        self.status_changed()

    def status(self):
        """Return the cheaply read status of each stored threat data source."""
        return threatdata.read_status(self.data_dir)

    def versions(self):
        """Return the loaded KEV and EPSS versions, or an empty string if no data has been loaded."""
        return self.threat_data.versions() if self.threat_data is not None else ""

    # ---- shell hooks ----
    def status_changed(self):
        """Ask the shell to redraw the status bar."""
        if self.shell is not None:
            self.shell.refresh_status()

    def show_view(self, name):
        """Switch to another view."""
        if self.shell is not None:
            self.shell.show_view(name)

    def settings_changed(self, settings):
        """Use new scoring settings everywhere."""
        self.settings = settings
        if self.shell is not None:
            self.shell.settings_changed()

    def prefs_changed(self, prefs):
        """Use new appearance preferences, rebuilding the window."""
        self.prefs = prefs
        if self.shell is not None:
            self.shell.prefs_changed()

    # ---- services views call, which tests replace ----
    def warn(self, title, message):
        """Show a warning dialog."""
        messagebox.showwarning(title, message, parent=self.root)

    def info(self, title, message):
        """Show an information dialog."""
        messagebox.showinfo(title, message, parent=self.root)

    def error(self, title, message):
        """Show an error dialog."""
        messagebox.showerror(title, message, parent=self.root)

    def confirm(self, title, message):
        """Ask an OK or Cancel question."""
        return messagebox.askokcancel(title, message, parent=self.root)

    def open_file(self, title, types):
        """Ask for an existing file; return its path or an empty string."""
        return filedialog.askopenfilename(parent=self.root, title=title, filetypes=types)

    def save_file(self, title, initial, types):
        """Ask where to save a file; return the path or an empty string."""
        return filedialog.asksaveasfilename(parent=self.root, title=title, initialfile=initial, defaultextension=".csv",
                                            filetypes=types)

    def copy(self, text):
        """Put text on the clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
