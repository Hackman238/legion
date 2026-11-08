"""Orderly teardown of the desktop UI's Qt objects.

PyQt6 segfaults at interpreter exit if the main window's widget tree is still alive once the
QApplication has been destroyed (Python tears the two down in an order Qt does not expect). So the
window must be destroyed explicitly, while the application object still exists, before the
interpreter exits; `legion.py` and the GUI tests both go through this helper.
"""
import gc


def destroy_main_window(main_window, app) -> None:
    """Delete main_window's Qt object tree now, while `app` (the QApplication) is still alive.

    Safe to call more than once and with a window that was never shown or only half built.
    """
    try:
        if main_window is not None:
            main_window.deleteLater()
    except RuntimeError:  # already deleted
        pass
    for _ in range(2):  # deleteLater needs an event-loop pass; the second pass collects the Python wrappers
        try:
            if app is not None:
                app.processEvents()
        except RuntimeError:
            break
        gc.collect()
