import os
import sys
import types
import unittest
from unittest.mock import patch


class PyShodanScriptApiKeyTest(unittest.TestCase):
    """The script carries no API key of its own: it comes from the caller or SHODAN_API_KEY."""

    def _fake_module(self, captured):
        class FakePyShodan:
            def __init__(self):
                self.apiKey = None

            def createSession(self):
                captured["apiKey"] = self.apiKey

            def searchIp(self, ip, allData=True):
                captured["ip"] = ip
                return {"latitude": "1.0", "asn": "AS64500"}

        module = types.ModuleType("pyShodan")
        module.PyShodan = FakePyShodan
        return module

    def test_lookup_uses_key_from_setter_without_env(self):
        from scripts.python.pyShodan import PyShodanScript

        captured = {}
        script = PyShodanScript()
        script.setApiKey("key-from-settings")
        env = dict(os.environ)
        env.pop("SHODAN_API_KEY", None)
        with patch.dict(os.environ, env, clear=True), patch.dict(sys.modules, {"pyShodan": self._fake_module(captured)}):
            result = script.lookup("203.0.113.7")
        self.assertEqual("key-from-settings", captured["apiKey"])
        self.assertEqual("203.0.113.7", captured["ip"])
        self.assertEqual("AS64500", result["asn"])

    def test_lookup_without_any_key_skips_instead_of_using_a_builtin_one(self):
        from scripts.python.pyShodan import PyShodanScript

        captured = {}
        env = dict(os.environ)
        env.pop("SHODAN_API_KEY", None)
        with patch.dict(os.environ, env, clear=True), patch.dict(sys.modules, {"pyShodan": self._fake_module(captured)}):
            self.assertEqual({}, PyShodanScript().lookup("203.0.113.7"))
        self.assertEqual({}, captured)  # no session was opened


if __name__ == "__main__":
    unittest.main()
