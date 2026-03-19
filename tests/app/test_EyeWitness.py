import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


class EyeWitnessHelpersTest(unittest.TestCase):
    def test_build_env_disables_cert_validation_helpers(self):
        from app.eyewitness import build_eyewitness_env

        env = build_eyewitness_env({})
        self.assertEqual("0", env.get("PYTHONHTTPSVERIFY"))
        self.assertEqual("", env.get("REQUESTS_CA_BUNDLE"))
        self.assertEqual("", env.get("CURL_CA_BUNDLE"))
        self.assertEqual("0", env.get("WDM_SSL_VERIFY"))

    def test_browser_tls_bypass_flags_cover_common_tls_warnings(self):
        from app.eyewitness import _browser_tls_bypass_flags

        flags = _browser_tls_bypass_flags()
        self.assertIn("--ignore-certificate-errors", flags)
        self.assertIn("--ignore-ssl-errors=yes", flags)
        self.assertIn("--allow-insecure-localhost", flags)
        self.assertIn("--allow-running-insecure-content", flags)
        self.assertIn("--disable-web-security", flags)
        self.assertIn("--test-type", flags)

    def test_build_command_wraps_text_script_without_shebang(self):
        from app.eyewitness import build_eyewitness_command

        with tempfile.TemporaryDirectory() as temp_dir:
            wrapper = os.path.join(temp_dir, "eyewitness")
            with open(wrapper, "w", encoding="utf-8") as handle:
                handle.write("python3 /opt/EyeWitness/Python/EyeWitness.py $@\n")
            os.chmod(wrapper, 0o755)

            command, resolved = build_eyewitness_command(
                url="http://127.0.0.1:8080",
                output_dir=os.path.join(temp_dir, "out"),
                delay=1,
                use_xvfb=False,
                executable=wrapper,
            )

        self.assertEqual(wrapper, resolved)
        self.assertTrue(command)
        self.assertEqual(wrapper, command[1])
        self.assertTrue(command[0].endswith("sh"))

    def test_find_eyewitness_screenshot_returns_png(self):
        from app.eyewitness import find_eyewitness_screenshot

        with tempfile.TemporaryDirectory() as temp_dir:
            screens_dir = os.path.join(temp_dir, "screens")
            nested_dir = os.path.join(temp_dir, "source")
            os.makedirs(screens_dir, exist_ok=True)
            os.makedirs(nested_dir, exist_ok=True)

            first = os.path.join(screens_dir, "first.png")
            second = os.path.join(nested_dir, "second.png")
            with open(first, "wb") as handle:
                handle.write(b"first")
            with open(second, "wb") as handle:
                handle.write(b"second")
            os.utime(second, (os.path.getatime(second), os.path.getmtime(second) + 1))

            found = find_eyewitness_screenshot(temp_dir)
            self.assertTrue(found.endswith(".png"))
            self.assertTrue(os.path.isfile(found))

    def test_summarize_failure_uses_last_stdout_line(self):
        from app.eyewitness import summarize_eyewitness_failure

        summary = summarize_eyewitness_failure([{
            "executable": "/usr/bin/eyewitness",
            "stdout": "banner line\nWebDriver.__init__() got an unexpected keyword argument 'capabilities'\n",
            "stderr": "",
            "error": "",
        }])
        self.assertIn("unexpected keyword argument", summary)

    @patch("app.eyewitness.resolve_eyewitness_executables")
    @patch("app.eyewitness.subprocess.run")
    def test_run_eyewitness_capture_success(self, mock_run, mock_resolve):
        from app.eyewitness import run_eyewitness_capture

        mock_resolve.return_value = ["/usr/bin/eyewitness"]

        def _run_side_effect(command, **_kwargs):
            output_dir = command[command.index("-d") + 1]
            screens = os.path.join(output_dir, "screens")
            os.makedirs(screens, exist_ok=True)
            with open(os.path.join(screens, "capture.png"), "wb") as handle:
                handle.write(b"png")
            return SimpleNamespace(returncode=0, stdout="ok", stderr="")

        mock_run.side_effect = _run_side_effect

        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_eyewitness_capture(
                url="http://127.0.0.1:8080",
                output_parent_dir=temp_dir,
                delay=1,
                use_xvfb=False,
                timeout=10,
            )
            self.assertTrue(result.get("ok"))
            self.assertTrue(os.path.isfile(result.get("screenshot_path", "")))

        self.assertEqual("completed", result.get("reason"))

    @patch("app.eyewitness.resolve_eyewitness_executables")
    @patch("app.eyewitness.subprocess.run")
    def test_run_eyewitness_capture_tries_next_executable_on_failure(self, mock_run, mock_resolve):
        from app.eyewitness import run_eyewitness_capture

        mock_resolve.return_value = ["/usr/local/bin/eyewitness", "/usr/bin/eyewitness"]
        call_count = {"n": 0}

        def _run_side_effect(command, **_kwargs):
            call_count["n"] += 1
            output_dir = command[command.index("-d") + 1]
            os.makedirs(output_dir, exist_ok=True)
            if call_count["n"] == 2:
                screens = os.path.join(output_dir, "screens")
                os.makedirs(screens, exist_ok=True)
                with open(os.path.join(screens, "capture.png"), "wb") as handle:
                    handle.write(b"png")
                return SimpleNamespace(returncode=0, stdout="ok", stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr="driver init failed")

        mock_run.side_effect = _run_side_effect

        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_eyewitness_capture(
                url="http://127.0.0.1:8080",
                output_parent_dir=temp_dir,
                delay=1,
                use_xvfb=False,
                timeout=10,
            )

        self.assertTrue(result.get("ok"))
        self.assertEqual(2, len(result.get("attempts", [])))
        self.assertEqual("/usr/bin/eyewitness", result.get("executable"))

    @patch("app.eyewitness._run_selenium_fallback_capture")
    @patch("app.eyewitness._run_selenium_chromium_fallback_capture")
    @patch("app.eyewitness._run_browser_cli_fallback_capture")
    @patch("app.eyewitness.resolve_eyewitness_executables")
    @patch("app.eyewitness.subprocess.run")
    def test_run_eyewitness_capture_uses_selenium_fallback(
            self,
            mock_run,
            mock_resolve,
            mock_browser_fallback,
            mock_chromium_fallback,
            mock_fallback,
    ):
        from app.eyewitness import run_eyewitness_capture

        mock_resolve.return_value = ["/usr/local/bin/eyewitness"]
        mock_run.return_value = SimpleNamespace(
            returncode=0,
            stdout="WebDriver.__init__() got an unexpected keyword argument 'capabilities'",
            stderr="",
        )
        mock_browser_fallback.return_value = {
            "ok": False,
            "executable": "chromium",
            "output_dir": "",
            "command": [],
            "error": "browser fallback timeout",
            "returncode": 124,
            "stdout": "",
            "stderr": "",
            "screenshot_path": None,
        }
        mock_chromium_fallback.return_value = {
            "ok": False,
            "executable": "selenium-chromium-direct",
            "output_dir": "",
            "command": [],
            "error": "selenium chromium fallback timeout",
            "returncode": 124,
            "stdout": "",
            "stderr": "",
            "screenshot_path": None,
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            fallback_png = os.path.join(temp_dir, "selenium-fallback", "screens", "capture.png")
            os.makedirs(os.path.dirname(fallback_png), exist_ok=True)
            with open(fallback_png, "wb") as handle:
                handle.write(b"png")
            mock_fallback.return_value = {
                "ok": True,
                "executable": "selenium-firefox-direct",
                "output_dir": os.path.dirname(os.path.dirname(fallback_png)),
                "command": ["selenium-firefox-direct", "http://127.0.0.1:8080"],
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "screenshot_path": fallback_png,
            }

            result = run_eyewitness_capture(
                url="http://127.0.0.1:8080",
                output_parent_dir=temp_dir,
                delay=1,
                use_xvfb=False,
                timeout=10,
            )

        self.assertTrue(result.get("ok"))
        self.assertEqual("selenium-firefox-direct", result.get("executable"))
        self.assertEqual(fallback_png, result.get("screenshot_path"))
        self.assertTrue(mock_fallback.called)
        self.assertTrue(mock_chromium_fallback.called)

    @patch("app.eyewitness._run_selenium_fallback_capture")
    @patch("app.eyewitness._run_selenium_chromium_fallback_capture")
    @patch("app.eyewitness._run_browser_cli_fallback_capture")
    @patch("app.eyewitness.resolve_eyewitness_executables")
    @patch("app.eyewitness.subprocess.run")
    def test_run_eyewitness_capture_uses_browser_fallback_after_selenium_chromium_failure(
            self,
            mock_run,
            mock_resolve,
            mock_browser_fallback,
            mock_chromium_fallback,
            mock_selenium_fallback,
    ):
        from app.eyewitness import run_eyewitness_capture

        mock_resolve.return_value = ["/usr/local/bin/eyewitness"]
        mock_run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="eyewitness failed")
        mock_chromium_fallback.return_value = {
            "ok": False,
            "executable": "selenium-chromium-direct",
            "output_dir": "",
            "command": [],
            "error": "selenium chromium fallback timeout",
            "returncode": 124,
            "stdout": "",
            "stderr": "",
            "screenshot_path": None,
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            fallback_png = os.path.join(temp_dir, "browser-fallback", "screens", "capture.png")
            os.makedirs(os.path.dirname(fallback_png), exist_ok=True)
            with open(fallback_png, "wb") as handle:
                handle.write(b"png")
            mock_browser_fallback.return_value = {
                "ok": True,
                "executable": "/usr/bin/chromium",
                "output_dir": os.path.dirname(os.path.dirname(fallback_png)),
                "command": ["/usr/bin/chromium", "--headless"],
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "screenshot_path": fallback_png,
            }

            result = run_eyewitness_capture(
                url="http://127.0.0.1:8080",
                output_parent_dir=temp_dir,
                delay=1,
                use_xvfb=False,
                timeout=10,
            )

        self.assertTrue(result.get("ok"))
        self.assertEqual("/usr/bin/chromium", result.get("executable"))
        self.assertEqual(fallback_png, result.get("screenshot_path"))
        self.assertTrue(mock_chromium_fallback.called)
        self.assertTrue(mock_browser_fallback.called)
        self.assertFalse(mock_selenium_fallback.called)

    @patch("app.eyewitness._resolve_browser_screenshot_executables")
    @patch("app.eyewitness._resolve_browser_screenshot_path")
    @patch("app.eyewitness.subprocess.run")
    def test_browser_cli_fallback_includes_tls_bypass_flags(
            self,
            mock_run,
            mock_resolve_path,
            mock_resolve_execs,
    ):
        from app.eyewitness import _run_browser_cli_fallback_capture

        mock_resolve_execs.return_value = ["/usr/bin/chromium"]
        mock_resolve_path.return_value = None
        commands = []

        def _run_side_effect(command, **_kwargs):
            commands.append(list(command))
            return SimpleNamespace(returncode=1, stdout="", stderr="privacy error")

        mock_run.side_effect = _run_side_effect

        with tempfile.TemporaryDirectory() as temp_dir:
            result = _run_browser_cli_fallback_capture(
                url="https://127.0.0.1:8443",
                output_parent_dir=temp_dir,
                timeout=10,
            )

        self.assertFalse(result.get("ok"))
        self.assertTrue(commands)
        first = commands[0]
        self.assertIn("--ignore-certificate-errors", first)
        self.assertIn("--ignore-ssl-errors=yes", first)
        self.assertIn("--allow-running-insecure-content", first)
        self.assertIn("--disable-web-security", first)
        self.assertIn("--test-type", first)

    @patch("app.eyewitness.subprocess.run")
    def test_selenium_chromium_fallback_script_tries_to_bypass_tls_interstitials(self, mock_run):
        from app.eyewitness import _run_selenium_chromium_fallback_capture

        captured = {}

        def _run_side_effect(command, **_kwargs):
            captured["command"] = list(command)
            return SimpleNamespace(returncode=1, stdout="", stderr="privacy error")

        mock_run.side_effect = _run_side_effect

        with tempfile.TemporaryDirectory() as temp_dir:
            result = _run_selenium_chromium_fallback_capture(
                url="https://127.0.0.1:8443",
                output_parent_dir=temp_dir,
                delay=1,
                timeout=10,
            )

        self.assertFalse(result.get("ok"))
        script = captured["command"][2]
        self.assertIn("acceptInsecureCerts", script)
        self.assertIn("--ignore-ssl-errors=yes", script)
        self.assertIn("--disable-web-security", script)
        self.assertIn("details-button", script)
        self.assertIn("proceed-link", script)

    @patch("app.eyewitness.subprocess.run")
    def test_selenium_firefox_fallback_script_tries_to_bypass_tls_interstitials(self, mock_run):
        from app.eyewitness import _run_selenium_fallback_capture

        captured = {}

        def _run_side_effect(command, **_kwargs):
            captured["command"] = list(command)
            return SimpleNamespace(returncode=1, stdout="", stderr="cert error")

        mock_run.side_effect = _run_side_effect

        with tempfile.TemporaryDirectory() as temp_dir:
            result = _run_selenium_fallback_capture(
                url="https://127.0.0.1:8443",
                output_parent_dir=temp_dir,
                delay=1,
                timeout=10,
            )

        self.assertFalse(result.get("ok"))
        script = captured["command"][2]
        self.assertIn("accept_insecure_certs=True", script)
        self.assertIn("browser.xul.error_pages.expert_bad_cert", script)
        self.assertIn("security.mixed_content.block_active_content", script)
        self.assertIn("advancedButton", script)
        self.assertIn("exceptionDialogButton", script)

    @patch("app.eyewitness._resolve_browser_screenshot_executables")
    @patch("app.eyewitness.subprocess.run")
    def test_browser_cli_fallback_detects_implicit_png_even_when_explicit_path_ignored(
            self,
            mock_run,
            mock_resolve,
    ):
        from app.eyewitness import _run_browser_cli_fallback_capture

        mock_resolve.return_value = ["/usr/bin/chromium-browser"]

        def _run_side_effect(_command, **kwargs):
            cwd = str(kwargs.get("cwd", ""))
            with open(os.path.join(cwd, "screenshot.png"), "wb") as handle:
                handle.write(b"png")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        mock_run.side_effect = _run_side_effect

        with tempfile.TemporaryDirectory() as temp_dir:
            result = _run_browser_cli_fallback_capture(
                url="https://127.0.0.1:8443",
                output_parent_dir=temp_dir,
                timeout=10,
            )
            self.assertTrue(result.get("ok"))
            screenshot_path = str(result.get("screenshot_path", ""))
            self.assertTrue(screenshot_path.endswith("capture.png"))
            self.assertTrue(os.path.isfile(screenshot_path))


if __name__ == "__main__":
    unittest.main()
