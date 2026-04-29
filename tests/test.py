import importlib
import importlib.util
import unittest


class LegacyImportSmokeTest(unittest.TestCase):
    def test_sqlalchemy_imports(self):
        importlib.import_module("sqlalchemy.orm.scoping")

    def test_pyqt6_imports(self):
        importlib.import_module("PyQt6.QtCore")
        importlib.import_module("PyQt6.QtGui")
        importlib.import_module("PyQt6.QtWidgets")

    @unittest.skipUnless(importlib.util.find_spec("quamash"), "quamash is not installed")
    def test_quamash_imports(self):
        importlib.import_module("asyncio")
        importlib.import_module("quamash")

    @unittest.skipUnless(importlib.util.find_spec("quamash"), "legacy Qt GUI imports require quamash")
    def test_legacy_legion_class_imports(self):
        for module_name in ("app.logic", "ui.gui", "ui.view", "controller.controller"):
            with self.subTest(module_name=module_name):
                importlib.import_module(module_name)


if __name__ == "__main__":
    unittest.main()
