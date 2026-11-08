import importlib
import unittest


class ImportSmokeTest(unittest.TestCase):
    def test_sqlalchemy_imports(self):
        importlib.import_module("sqlalchemy.orm.scoping")

    def test_runtime_entry_modules_import_without_qt(self):
        for module_name in ("app.logic", "app.web", "app.web.runtime", "app.importers.nmap_runner", "app.mcpServer"):
            with self.subTest(module_name=module_name):
                importlib.import_module(module_name)


if __name__ == "__main__":
    unittest.main()
