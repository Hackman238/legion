import os
import tempfile
import unittest

from app.core.config_store import IniSettingsStore


class IniSettingsStoreToleranceTest(unittest.TestCase):
    def _store(self, content: bytes):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = os.path.join(self.tmp.name, "legion.conf")
        with open(path, "wb") as handle:
            handle.write(content)
        return IniSettingsStore(path)

    def test_duplicate_sections_and_options_do_not_abort_startup(self):
        store = self._store(b"[HostActions]\na=1, x\n[HostActions]\na=2, y\nb=3, z\n")
        store.beginGroup("HostActions")
        self.assertEqual(sorted(store.childKeys()), ["a", "b"])

    def test_unparseable_file_falls_back_to_empty_config(self):
        store = self._store(b"this is not an ini file\n")
        store.beginGroup("GeneralSettings")
        self.assertEqual([], store.childKeys())

    def test_non_utf8_bytes_are_replaced_not_fatal(self):
        store = self._store(b"[GeneralSettings]\nname=caf\xe9\n")
        store.beginGroup("GeneralSettings")
        self.assertIn("name", store.childKeys())

    def test_sync_replaces_file_atomically(self):
        store = self._store(b"[GeneralSettings]\nname=a\n")
        store.beginGroup("GeneralSettings")
        store.setValue("name", "b")
        store.sync()
        self.assertFalse([f for f in os.listdir(self.tmp.name) if ".tmp-" in f])
        with open(os.path.join(self.tmp.name, "legion.conf"), encoding="utf-8") as handle:
            self.assertIn("name=b", handle.read())


if __name__ == "__main__":
    unittest.main()
