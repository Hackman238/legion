import builtins
import os
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6 import QtWidgets

import controller.controller as controller_module

CONTROLLER_SOURCE = os.path.join(os.path.dirname(controller_module.__file__), "controller.py")


class ControllerModuleNamesTest(unittest.TestCase):
    def test_names_used_by_the_controller_are_defined(self):
        # Star imports hide undefined names from pyflakes ("may be undefined, or defined from star imports"),
        # so check that every such name really resolves on the imported module.
        try:
            from pyflakes.api import check
            from pyflakes.reporter import Reporter
        except ImportError:
            self.skipTest("pyflakes is not installed")
        import io
        warnings = io.StringIO()
        with open(CONTROLLER_SOURCE, encoding="utf-8") as handle:
            check(handle.read(), CONTROLLER_SOURCE, Reporter(warnings, io.StringIO()))
        names = set()
        for line in warnings.getvalue().splitlines():
            match = re.search(r"undefined name '([^']+)'|'([^']+)' may be undefined", line)
            if match:
                names.add(match.group(1) or match.group(2))
        missing = sorted(name for name in names
                         if not hasattr(controller_module, name) and not hasattr(builtins, name))
        self.assertEqual([], missing)

    def test_gui_only_helpers_are_importable_from_the_controller(self):
        for name in ("BrowserOpener", "MyQProcess", "QMenu", "QMessageBox"):
            self.assertTrue(hasattr(controller_module, name), name)


class ControllerGuiStartupTest(unittest.TestCase):
    """Builds the real desktop Controller/View offscreen, as legion.py does."""

    @classmethod
    def setUpClass(cls):
        cls._qt_app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="legion-gui-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        env = patch.dict(os.environ, {"LEGION_HOME": self.tmp})
        env.start()
        self.addCleanup(env.stop)
        import app.ProjectManager as pm_module
        temp_dir = patch.object(pm_module, "tempDirectory", self.tmp)
        temp_dir.start()
        self.addCleanup(temp_dir.stop)

    def _build(self):
        from app.ProjectManager import ProjectManager
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.logic import Logic
        from app.shell.DefaultShell import DefaultShell
        from app.tools.ToolCoordinator import ToolCoordinator
        from app.tools.nmap.DefaultNmapExporter import DefaultNmapExporter
        from db.RepositoryFactory import RepositoryFactory
        from ui.ViewState import ViewState
        from ui.gui import Ui_MainWindow
        from ui.view import View

        main_window = QtWidgets.QMainWindow()
        # Qt objects live on self for the test and are destroyed explicitly afterwards, while the
        # QApplication still exists; a window left to interpreter teardown segfaults (see ui/qt_shutdown.py).
        self._qt_refs = [main_window]
        ui = Ui_MainWindow()
        ui.setupUi(main_window)
        shell = DefaultShell()
        project_manager = ProjectManager(shell, RepositoryFactory(getDbLogger()), getAppLogger())
        logic = Logic(shell, project_manager,
                      ToolCoordinator(shell, DefaultNmapExporter(shell, getAppLogger())))
        logic.createNewTemporaryProject()
        view = View(ViewState(), ui, main_window, shell, self._qt_app, None)
        self._qt_refs.extend((ui, view, logic))
        self.addCleanup(self._teardown, main_window, view, logic)
        ctrl = controller_module.Controller(view, logic)
        self._qt_refs.append(ctrl)
        return ctrl, view

    def _teardown(self, main_window, view, logic):
        from ui.qt_shutdown import destroy_main_window

        ctrl = getattr(view, "controller", None)
        for timer in (getattr(ctrl, "updateUITimer", None), getattr(ctrl, "updateUI2Timer", None),
                      getattr(ctrl, "processTableUiUpdateTimer", None),
                      getattr(view, "_notes_autosave_timer", None)):
            if timer is not None:
                timer.stop()
        view._app_exit_in_progress = True  # don't re-create the screenshooter while closing
        if ctrl is not None and hasattr(ctrl, "processTableUiUpdateTimer"):
            ctrl.closeProject()
        else:  # construction failed part-way: just release the temporary project
            logic.activeProject.database.dispose()
        self._qt_refs.clear()
        destroy_main_window(main_window, self._qt_app)

    def test_controller_starts(self):
        ctrl, _view = self._build()
        self.assertIsInstance(ctrl.browser, controller_module.BrowserOpener)

    def test_import_end_hides_the_import_progress_bar(self):
        ctrl, view = self._build()
        view.showImportProgress()
        self.assertTrue(view.importInProgress)

        ctrl.nmapImporter.done.emit()

        self.assertFalse(view.importInProgress)
        self.assertTrue(view.importProgressBar.isHidden())
        self.assertTrue(view.cancelImportButton.isHidden())

    def test_import_end_releases_a_database_retired_by_save_as(self):
        from unittest.mock import MagicMock

        ctrl, _view = self._build()
        retired = MagicMock()
        ctrl.logic.retireDatabase(retired)

        ctrl.nmapImporter.finished.emit()   # the import was the last thing that could still use it
        self._qt_app.processEvents()        # runs the deferred idle check

        retired.dispose.assert_called_once_with()
        self.assertFalse(ctrl.logic.hasRetiredDatabases())

    def test_import_failure_also_clears_the_import_state(self):
        ctrl, view = self._build()
        view.showImportProgress()

        ctrl.nmapImporter.failed.emit("boom")

        self.assertFalse(view.importInProgress)
        self.assertTrue(view.importProgressBar.isHidden())


if __name__ == "__main__":
    unittest.main()
