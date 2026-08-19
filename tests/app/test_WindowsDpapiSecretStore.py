import os
import stat
import tempfile
import unittest
from unittest.mock import patch


class WindowsDpapiSecretBackendTest(unittest.TestCase):
    def test_encrypted_records_round_trip_without_plaintext_on_disk(self):
        from app.core.windows_dpapi_secret_store import WindowsDpapiSecretBackend

        temp_parent = "/tmp" if os.path.isdir("/tmp") else None
        with tempfile.TemporaryDirectory(dir=temp_parent) as tmpdir:
            storage_path = os.path.join(tmpdir, "secrets.dpapi.json")
            backend = WindowsDpapiSecretBackend("powershell.exe", storage_path)

            with patch.object(backend, "_encrypt", side_effect=lambda value: f"encrypted:{value[::-1]}"), patch.object(
                    backend,
                    "_decrypt",
                    side_effect=lambda value: value.removeprefix("encrypted:")[::-1],
            ):
                backend.set_secret("scheduler.providers.openai.api_key", "sk-test-openai")
                self.assertEqual(
                    "sk-test-openai",
                    backend.get_secret("scheduler.providers.openai.api_key"),
                )
                with open(storage_path, "r", encoding="utf-8") as handle:
                    persisted = handle.read()
                self.assertNotIn("sk-test-openai", persisted)
                self.assertEqual(0o600, stat.S_IMODE(os.stat(storage_path).st_mode))

                backend.delete_secret("scheduler.providers.openai.api_key")
                self.assertEqual("", backend.get_secret("scheduler.providers.openai.api_key"))

    def test_backend_is_not_selected_outside_wsl(self):
        from app.core.windows_dpapi_secret_store import WindowsDpapiSecretBackend

        with patch.dict(os.environ, {"WSL_DISTRO_NAME": ""}, clear=False), patch(
                "app.core.windows_dpapi_secret_store.platform.release",
                return_value="6.8.0-linux",
        ), patch("app.core.windows_dpapi_secret_store.shutil.which") as which:
            self.assertIsNone(WindowsDpapiSecretBackend.create_if_available())
            which.assert_not_called()


if __name__ == "__main__":
    unittest.main()
