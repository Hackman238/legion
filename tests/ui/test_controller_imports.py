import os
import unittest


class ControllerImportsTest(unittest.TestCase):
    def test_browser_opener_symbol_is_available_to_controller(self):
        import controller.controller as controller_module

        self.assertTrue(
            hasattr(controller_module, "BrowserOpener"),
            "controller.controller must import BrowserOpener explicitly "
            "(initBrowserOpener uses the bare name at startup)",
        )

    def test_myqprocess_symbol_is_available_to_controller(self):
        import controller.controller as controller_module
        from app.auxiliary import MyQProcess

        self.assertIs(
            controller_module.MyQProcess,
            MyQProcess,
            "controller.controller must import MyQProcess explicitly "
            "(runCommand/runStagedNmap use the bare name; a NameError in a "
            "Qt slot aborts the whole PyQt6 process)",
        )

    def test_controller_has_no_unresolved_global_names(self):
        # Star imports (app.logic/app.settings) blind pyflakes to missing
        # names, which previously hid MyQProcess/QtCore NameErrors that
        # aborted the GUI mid-scan. Resolve every global the module
        # references against its real namespace.
        import builtins
        import symtable

        import controller.controller as controller_module

        source = open(controller_module.__file__, encoding="utf-8").read()
        missing = set()

        def walk(table):
            for sym in table.get_symbols():
                if sym.is_global() and sym.is_referenced() and not sym.is_assigned():
                    name = sym.get_name()
                    if name not in controller_module.__dict__ and not hasattr(builtins, name):
                        missing.add(name)
            for child in table.get_children():
                walk(child)

        walk(symtable.symtable(source, controller_module.__file__, "exec"))
        self.assertEqual(set(), missing)

    def test_darwin_terminal_argv_uses_absolute_exec_in_shell(self):
        from controller.controller import Controller

        argv = Controller._darwin_terminal_argv('nmap -sV "10.0.0.1"')
        self.assertEqual("osascript", argv[0])
        script = argv[2]
        self.assertNotIn("./scripts/exec-in-shell", script)
        exec_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(
                __import__("controller.controller", fromlist=["__file__"]).__file__))),
            "scripts", "exec-in-shell",
        )
        self.assertTrue(os.path.exists(exec_path))
        self.assertIn(exec_path, script)
        # Double quotes from the tool command are escaped for AppleScript.
        self.assertIn('\\"', script)


if __name__ == "__main__":
    unittest.main()
