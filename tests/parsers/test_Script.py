import unittest
from unittest.mock import patch

import parsers.Script as script_module
from parsers.Parser import MalformedXmlDocumentException
from parsers.Script import Script

VULNERS_OUTPUT = (
    "\n  cpe:/a:openbsd:openssh:8.4p1: \n"
    "    \tPACKETSTORM:173661\t9.8\thttps://vulners.com/packetstorm/PACKETSTORM:173661\t*EXPLOIT*\n"
    "    \tCVE-2023-38408\t9.8\thttps://vulners.com/cve/CVE-2023-38408\n"
    "    \tSSV:92579\t7.5\thttps://vulners.com/seebug/SSV:92579\t*EXPLOIT*\n"
    "    \tCVE-2021-41617\t7.0\thttps://vulners.com/cve/CVE-2021-41617\n"
)


class ScriptVulnersTest(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(script_module, "getPyExploitDb", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_non_cve_lines_are_skipped_without_losing_or_duplicating_cves(self):
        results = Script(None).processVulnersScriptOutput(VULNERS_OUTPUT)
        self.assertEqual(["openssh"], list(results.keys()))
        self.assertEqual(["CVE-2023-38408", "CVE-2021-41617"], [item["id"] for item in results["openssh"]])

    def test_getCves_returns_cves_when_first_entry_is_not_a_cve(self):
        script = Script(None)
        script.scriptId = "vulners"
        script.output = VULNERS_OUTPUT
        self.assertEqual(["CVE-2023-38408", "CVE-2021-41617"], [item.name for item in script.getCves()])


class PyExploitDbCacheTest(unittest.TestCase):
    def setUp(self):
        self._saved = (script_module._PY_EXPLOIT_DB_INSTANCE, script_module._PY_EXPLOIT_DB_INIT_ATTEMPTED,
                       script_module._PY_EXPLOIT_DB_RETRY_AFTER)
        script_module._PY_EXPLOIT_DB_INSTANCE = None
        script_module._PY_EXPLOIT_DB_INIT_ATTEMPTED = False
        script_module._PY_EXPLOIT_DB_RETRY_AFTER = 0.0

    def tearDown(self):
        (script_module._PY_EXPLOIT_DB_INSTANCE, script_module._PY_EXPLOIT_DB_INIT_ATTEMPTED,
         script_module._PY_EXPLOIT_DB_RETRY_AFTER) = self._saved

    def _package_dir(self, with_csv=True):
        import json
        import os
        import tempfile

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with open(os.path.join(tmp.name, "cveToEdbid.json"), "w", encoding="utf-8") as handle:
            json.dump({"CVE-2023-38408": ["51234"]}, handle)
        if with_csv:
            os.makedirs(os.path.join(tmp.name, "exploit-database"))
            with open(os.path.join(tmp.name, "exploit-database", "files_exploits.csv"), "w", encoding="utf-8") as handle:
                handle.write("id,file,description\n51234,exploits/linux/remote/51234.py,OpenSSH agent RCE\n")
        return tmp.name

    def test_exploit_db_is_loaded_once_and_used_for_vulners_cves(self):
        package_dir = self._package_dir()
        with patch.object(script_module, "_find_exploit_db_package_dir", return_value=package_dir) as finder:
            first = script_module.getPyExploitDb()
            results = Script(None).processVulnersScriptOutput(VULNERS_OUTPUT)
            Script(None).processVulnersScriptOutput(VULNERS_OUTPUT)
            self.assertIs(first, script_module.getPyExploitDb())
        finder.assert_called_once_with()
        enriched = {item["id"]: item for item in results["openssh"]}["CVE-2023-38408"]
        self.assertEqual("51234", enriched["exploitId"])
        self.assertEqual("https://www.exploit-db.com/exploits/51234", enriched["exploitUrl"])
        self.assertEqual("OpenSSH agent RCE", enriched["exploit"])

    def test_lookups_work_without_the_exploit_csv(self):
        with patch.object(script_module, "_find_exploit_db_package_dir", return_value=self._package_dir(False)):
            self.assertEqual({"id": "51234", "description": "", "file": ""},
                             script_module.getPyExploitDb().searchCve("cve-2023-38408"))

    def test_loading_never_runs_the_library_network_refresh(self):
        # The library's openFile()/updateDb() clone/pull exploit-db (and some versions crawl it); importing an
        # nmap XML must not trigger them, so the library class is not even imported.
        with patch.object(script_module, "_find_exploit_db_package_dir", return_value=self._package_dir()), \
                patch("importlib.import_module", side_effect=AssertionError("library imported")):
            self.assertIsNotNone(script_module.getPyExploitDb())

    def test_missing_package_disables_enrichment(self):
        with patch.object(script_module, "_find_exploit_db_package_dir", return_value=None):
            self.assertIsNone(script_module.getPyExploitDb())

    def test_missing_data_file_disables_enrichment_once(self):
        import os

        package_dir = self._package_dir()
        os.remove(os.path.join(package_dir, "cveToEdbid.json"))
        with patch.object(script_module, "_find_exploit_db_package_dir", return_value=package_dir) as finder:
            self.assertIsNone(script_module.getPyExploitDb())
            self.assertIsNone(script_module.getPyExploitDb())
        finder.assert_called_once_with()  # not retried (and not logged) again

    def test_only_needed_exploit_columns_are_kept(self):
        with patch.object(script_module, "_find_exploit_db_package_dir", return_value=self._package_dir()):
            db = script_module.getPyExploitDb()
        self.assertEqual({"51234": ("OpenSSH agent RCE", "exploits/linux/remote/51234.py")}, db.exploits_by_edbid)

    def test_failed_load_is_retried_after_cooldown(self):
        import os

        package_dir = self._package_dir()
        data_file = os.path.join(package_dir, "cveToEdbid.json")
        with open(data_file, encoding="utf-8") as handle:
            good = handle.read()
        with open(data_file, "w", encoding="utf-8") as handle:
            handle.write("{truncated")  # e.g. being rewritten by primeExploitDb.py
        clock = {"now": 0.0}
        with patch.object(script_module, "_find_exploit_db_package_dir", return_value=package_dir), \
                patch.object(script_module.time, "monotonic", side_effect=lambda: clock["now"]):
            self.assertIsNone(script_module.getPyExploitDb())      # fails, cooldown until 60s
            with open(data_file, "w", encoding="utf-8") as handle:
                handle.write(good)
            clock["now"] = 1.0
            self.assertIsNone(script_module.getPyExploitDb())      # still cooling down, no retry
            clock["now"] = 100.0
            self.assertIsNotNone(script_module.getPyExploitDb())   # retried after cooldown


class MalformedXmlExceptionTest(unittest.TestCase):
    def test_is_caught_by_generic_exception_handlers(self):
        self.assertTrue(issubclass(MalformedXmlDocumentException, Exception))


class VulnersSoftwareHeaderTest(unittest.TestCase):
    OUTPUT = (
        "\n  nginx 1.14.0: \n"
        "    \tCVE-2019-20372\t5.3\thttps://vulners.com/cve/CVE-2019-20372\n"
        "  cpe:/a:openbsd:openssh:7.4: \n"
        "    \tCVE-2023-38408\t9.8\thttps://vulners.com/cve/CVE-2023-38408\n"
    )

    def test_products_without_a_cpe_are_parsed(self):
        from parsers.Script import Script
        self.assertEqual({("nginx", "1.14.0"), ("openssh", "7.4")}, Script.vulnersProductVersions(self.OUTPUT))
        results = Script(None).processVulnersScriptOutput(self.OUTPUT)
        self.assertEqual({"nginx", "openssh"}, set(results))
        self.assertEqual("CVE-2019-20372", results["nginx"][0]["id"])
        self.assertEqual("software", results["nginx"][0]["source"])


if __name__ == "__main__":
    unittest.main()
