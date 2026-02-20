import os
import tempfile
import unittest

from app.hostsfile import LEGION_TEMP_BEGIN, LEGION_TEMP_END, add_temporary_host_alias


class HostsFileTest(unittest.TestCase):
    def test_adds_entry_in_legion_block(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_path = os.path.join(tmpdir, "hosts")
            with open(hosts_path, "w", encoding="utf-8") as handle:
                handle.write("127.0.0.1 localhost\n")

            ok, reason = add_temporary_host_alias("192.168.3.1", "unifi.local", hosts_path=hosts_path)
            self.assertTrue(ok)
            self.assertEqual("added", reason)

            text = self._read_file(hosts_path)
            self.assertIn(LEGION_TEMP_BEGIN, text)
            self.assertIn(LEGION_TEMP_END, text)
            self.assertIn("192.168.3.1\tunifi.local", text)

    def test_does_not_duplicate_existing_alias(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_path = os.path.join(tmpdir, "hosts")
            with open(hosts_path, "w", encoding="utf-8") as handle:
                handle.write("127.0.0.1 localhost\n")

            first_ok, _ = add_temporary_host_alias("192.168.3.1", "unifi.local", hosts_path=hosts_path)
            second_ok, second_reason = add_temporary_host_alias("192.168.3.1", "unifi.local", hosts_path=hosts_path)
            self.assertTrue(first_ok)
            self.assertTrue(second_ok)
            self.assertEqual("already-present", second_reason)

            text = self._read_file(hosts_path)
            self.assertEqual(1, text.count("192.168.3.1\tunifi.local"))

    def test_rejects_collision_with_existing_hostname(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_path = os.path.join(tmpdir, "hosts")
            with open(hosts_path, "w", encoding="utf-8") as handle:
                handle.write("10.0.0.9 unifi.local\n")

            ok, reason = add_temporary_host_alias("192.168.3.1", "unifi.local", hosts_path=hosts_path)
            self.assertFalse(ok)
            self.assertEqual("hostname-collision", reason)

            text = self._read_file(hosts_path)
            self.assertNotIn(LEGION_TEMP_BEGIN, text)

    @staticmethod
    def _read_file(path):
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()


if __name__ == "__main__":
    unittest.main()
