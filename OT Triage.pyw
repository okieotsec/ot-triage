"""Double-click to start OT Triage.

Needs Python 3.12 or newer with Tkinter (the installer from python.org includes it). On Windows a .pyw file runs
without a console window, so a problem at start-up is shown in a message box instead of disappearing.
"""
import sys

MINIMUM = (3, 12)


def report(text):
    """Show a start-up problem where the person will see it."""
    try:
        import tkinter
        from tkinter import messagebox
        root = tkinter.Tk()
        root.withdraw()
        messagebox.showerror("OT Triage could not start", text)
    except Exception:  # noqa: BLE001  # no usable Tk either, so the console is all that is left
        sys.stderr.write(text + "\n")


def main():
    """Start the application, or say why it cannot start."""
    if sys.version_info < MINIMUM:
        report(f"OT Triage needs Python {MINIMUM[0]}.{MINIMUM[1]} or newer; this is "
               f"{sys.version_info[0]}.{sys.version_info[1]}.")
        return 1
    try:
        import ot_triage_gui
    except ImportError as error:
        report(f"OT Triage could not load a part of itself ({error}). Keep the whole folder together, and use a "
               "Python that includes Tkinter.")
        return 1
    ot_triage_gui.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
