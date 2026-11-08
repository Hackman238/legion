import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from app.cli_utils import build_hosts_export, import_targets
from db.SqliteDbAdapter import Database
from db.entities.cve import cve
from db.entities.host import hostObj
from db.entities.l1script import l1ScriptObj
from db.entities.note import note
from db.entities.port import portObj
from db.entities.service import serviceObj


class CliUtilsBatchingTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.db = Database(os.path.join(self.tempdir.name, "project.legion"))
        self.addCleanup(self.db.dispose)

    def test_import_targets_skips_existing_and_commits_once(self):
        session = self.db.session()
        session.add(hostObj(ip="10.0.0.1", hostname="known.example"))
        session.commit()

        host_repo = MagicMock()
        with patch.object(session, "commit", wraps=session.commit) as commit_spy:
            added = import_targets(
                session, host_repo,
                ["10.0.0.1", "known.example", "10.0.0.2", "http://new.example/path", "10.0.0.2", "# comment", ""],
            )
        session.close()

        self.assertEqual(["10.0.0.2", "new.example"], added)
        commit_spy.assert_called_once_with()
        host_repo.getHostInformation.assert_not_called()
        session = self.db.session()
        try:
            self.assertEqual(3, session.query(hostObj).count())
        finally:
            session.close()

    def test_import_targets_falls_back_to_per_target_commits(self):
        session = self.db.session()
        real_commit = session.commit
        calls = {"n": 0}

        def flaky_commit():
            calls["n"] += 1
            if calls["n"] in (1, 3):  # the batch commit and the second single-target commit fail
                raise RuntimeError("database is locked")
            real_commit()

        with patch.object(session, "commit", side_effect=flaky_commit):
            added = import_targets(session, MagicMock(), ["10.0.0.5", "10.0.0.6", "10.0.0.7"])
        session.close()

        self.assertEqual(["10.0.0.5", "10.0.0.7"], added)
        session = self.db.session()
        try:
            self.assertEqual({"10.0.0.5", "10.0.0.7"}, {row.ip for row in session.query(hostObj).all()})
        finally:
            session.close()

    def test_failed_lookup_chunk_only_skips_its_own_targets(self):
        from app import cli_utils

        session = self.db.session()
        targets = [f"10.1.{i // 250}.{i % 250}" for i in range(cli_utils._IMPORT_LOOKUP_CHUNK + 3)]
        real_query = session.query
        calls = {"n": 0}

        def flaky_query(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("database is locked")
            return real_query(*args, **kwargs)

        with patch.object(session, "query", side_effect=flaky_query):
            added = import_targets(session, MagicMock(), targets)
        session.close()

        self.assertEqual(targets[cli_utils._IMPORT_LOOKUP_CHUNK:], added)

    def test_build_hosts_export_groups_rows_per_host(self):
        session = self.db.session()
        host_a = hostObj(ip="10.0.0.1", hostname="a")
        host_b = hostObj(ip="10.0.0.2", hostname="b")
        session.add_all([host_a, host_b])
        session.flush()
        service = serviceObj("ssh", host_a.id, "OpenSSH", "8.4")
        session.add(service)
        session.flush()
        port_a = portObj("22", "tcp", "open", host_a.id, service.id)
        port_b = portObj("80", "tcp", "open", host_b.id, "")
        session.add_all([port_a, port_b])
        session.flush()
        session.add(l1ScriptObj("vulners", "output", port_a.id, host_a.id))
        session.add(note(host_a.id, "Added by nmap"))
        session.add(cve(name="CVE-2023-38408", url="u", product="openssh", hostId=host_a.id, severity="9.8"))
        session.commit()
        session.close()

        exported = build_hosts_export(self.db)

        by_ip = {item["ip"]: item for item in exported}
        self.assertEqual({"10.0.0.1", "10.0.0.2"}, set(by_ip))
        host_a_export = by_ip["10.0.0.1"]
        self.assertEqual("Added by nmap", host_a_export["note"])
        self.assertEqual(["22"], [p["portId"] for p in host_a_export["ports"]])
        self.assertEqual("ssh", host_a_export["ports"][0]["service"]["name"])
        self.assertEqual(["vulners"], [s["scriptId"] for s in host_a_export["ports"][0]["scripts"]])
        self.assertEqual("CVE-2023-38408", host_a_export["cves"][0]["name"])
        self.assertEqual("9.8", host_a_export["cves"][0]["severity"])
        # every CVE column is exported, as the former cve.__dict__ export did (consumers key on id/hostId)
        self.assertEqual(str(host_a_export["id"]), str(host_a_export["cves"][0]["hostId"]))
        self.assertIn("id", host_a_export["cves"][0])
        self.assertIn("serviceId", host_a_export["cves"][0])

        host_b_export = by_ip["10.0.0.2"]
        self.assertEqual("", host_b_export["note"])
        self.assertEqual([], host_b_export["cves"])
        self.assertNotIn("service", host_b_export["ports"][0])
        self.assertEqual([], host_b_export["ports"][0]["scripts"])


if __name__ == "__main__":
    unittest.main()
