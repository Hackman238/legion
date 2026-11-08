import os
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6 import QtWidgets

from ui.view import View

SAVE = QtWidgets.QMessageBox.StandardButton.Save
DISCARD = QtWidgets.QMessageBox.StandardButton.Discard
CANCEL = QtWidgets.QMessageBox.StandardButton.Cancel


def _make_view(first_save=True, import_running=False):
    view = View.__new__(View)  # the save/close prompts only use the attributes below
    view.ui = MagicMock()
    view.controller = MagicMock()
    view.controller.isImportRunning.return_value = import_running
    view.controller.getRunningProcesses.return_value = []
    view.viewState = SimpleNamespace(dirty=True, firstSave=first_save, lastHostIdClicked="")
    view.setDirty = MagicMock()
    view._autoSaveNotesIfDirty = MagicMock(return_value=True)
    return view


@patch("ui.view.QtWidgets.QMessageBox.information")
@patch("ui.view.QtWidgets.QMessageBox.question")
class ViewSaveOrDiscardTest(unittest.TestCase):
    def test_save_refused_during_import_cancels_new_open_exit(self, question, _information):
        question.return_value = SAVE
        view = _make_view(first_save=True, import_running=True)

        self.assertFalse(view.saveProjectAs())
        self.assertFalse(view.saveOrDiscard())
        self.assertFalse(view.dealWithCurrentProject())
        self.assertFalse(view.dealWithCurrentProject(exiting=True))
        view.controller.saveProjectAs.assert_not_called()

    @patch("ui.view.QtWidgets.QFileDialog.getSaveFileName", return_value=("", ""))
    def test_cancelled_save_as_dialog_cancels(self, _dialog, question, _information):
        question.return_value = SAVE
        view = _make_view(first_save=True)
        self.assertFalse(view.saveOrDiscard())

    @patch("ui.view.QtWidgets.QFileDialog.getSaveFileName")
    def test_successful_save_as_proceeds(self, dialog, question, _information):
        question.return_value = SAVE
        view = _make_view(first_save=True)
        dialog.return_value = (os.path.join(os.getcwd(), "saved.legion"), "")
        view.controller.saveProjectAs.return_value = True

        self.assertTrue(view.saveOrDiscard())
        view.setDirty.assert_called_once_with(False)

    @patch("ui.view.QtWidgets.QFileDialog.getSaveFileName")
    def test_failed_save_to_a_new_path_does_not_offer_to_replace(self, dialog, question, _information):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            view = _make_view(first_save=True)
            dialog.return_value = (os.path.join(tmpdir, "new"), "")  # no such file
            view.controller.saveProjectAs.return_value = False         # e.g. integrity error, already reported

            self.assertFalse(view.saveProjectAs())

        question.assert_not_called()                                    # no bogus "already exists" prompt
        view.controller.saveProjectAs.assert_called_once()              # and no forced replace retry
        view.setDirty.assert_not_called()

    @patch("ui.view.QtWidgets.QFileDialog.getSaveFileName")
    def test_existing_other_file_asks_before_replacing(self, dialog, question, _information):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            existing = os.path.join(tmpdir, "other.legion")
            open(existing, "w").close()
            view = _make_view(first_save=True)
            view.controller.logic.activeProject.properties.projectName = os.path.join(tmpdir, "current.legion")
            dialog.return_value = (existing, "")
            question.return_value = SAVE
            view.controller.saveProjectAs.return_value = True

            self.assertTrue(view.saveProjectAs())

        question.assert_called_once()
        view.controller.saveProjectAs.assert_called_once_with(existing, 1)

    def test_save_of_an_already_saved_project_reports_its_outcome(self, question, _information):
        question.return_value = SAVE
        view = _make_view(first_save=False)
        view.controller.saveProject.return_value = True
        self.assertTrue(view.saveOrDiscard())
        view.controller.saveProject.return_value = False
        self.assertFalse(view.saveOrDiscard())

    def test_discard_and_cancel(self, question, _information):
        view = _make_view()
        question.return_value = DISCARD
        self.assertTrue(view.saveOrDiscard())
        question.return_value = CANCEL
        self.assertFalse(view.saveOrDiscard())


if __name__ == "__main__":
    unittest.main()
