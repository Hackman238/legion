import os
import sys
import types
import unittest
from unittest.mock import patch


class PyShodanScriptApiKeyTest(unittest.TestCase):
    def test_lookup_uses_key_from_setter_without_env(self):
        from scripts.python.pyShodan import PyShodanScript

        captured = {}

        class FakePyShodan:
            def __init__(self):
                self.apiKey = None

            def createSession(self):
                captured["apiKey"] = self.apiKey

            def searchIp(self, ip, allData=True):
                captured["ip"] = ip
                return {"latitude": "1.0", "asn": "AS64500"}

        fake_module = types.ModuleType("pyShodan")
        fake_module.PyShodan = FakePyShodan

        script = PyShodanScript()
        script.setApiKey("key-from-settings")
        env = dict(os.environ)
        env.pop("SHODAN_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            with patch.dict(sys.modules, {"pyShodan": fake_module}):
                result = script.lookup("203.0.113.7")

        self.assertEqual("key-from-settings", captured["apiKey"])
        self.assertEqual("203.0.113.7", captured["ip"])
        self.assertEqual("AS64500", result["asn"])


if __name__ == "__main__":
    unittest.main()
