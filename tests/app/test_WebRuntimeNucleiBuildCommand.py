import unittest
from types import SimpleNamespace


class WebRuntimeNucleiBuildCommandTest(unittest.TestCase):
    def test_build_command_keeps_output_filename_and_adds_as(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._require_active_project = lambda: SimpleNamespace(
            properties=SimpleNamespace(runningFolder="/tmp/legion-test-running")
        )

        template = (
            "(command -v nuclei >/dev/null 2>&1 && "
            "(nuclei -u https://[IP]:[PORT] -ni -silent -no-color -o [OUTPUT].txt || "
            "nuclei -u http://[IP]:[PORT] -ni -silent -no-color -o [OUTPUT].txt)) || echo nuclei not found"
        )

        command, outputfile = runtime._build_command(template, "192.168.3.1", "80", "tcp", "nuclei-web")

        self.assertIn("command -v nuclei >/dev/null 2>&1", command)
        self.assertIn("nuclei -as -u https://192.168.3.1:80", command)
        self.assertIn("nuclei -as -u http://192.168.3.1:80", command)
        self.assertIn(f"{outputfile}.txt", command)
        self.assertIn("-nuclei-web-192.168.3.1-80", outputfile)
        self.assertNotIn("nuclei -as >/dev/null", command)
        self.assertNotIn("nuclei -as-web", command)

    def test_build_command_normalizes_legacy_gobuster_dir_template(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._require_active_project = lambda: SimpleNamespace(
            properties=SimpleNamespace(runningFolder="/tmp/legion-test-running")
        )

        template = (
            "(command -v feroxbuster >/dev/null 2>&1 && "
            "(feroxbuster -u https://[IP]:[PORT] -k --silent -o [OUTPUT].txt || "
            "feroxbuster -u http://[IP]:[PORT] --silent -o [OUTPUT].txt)) || "
            "(command -v gobuster >/dev/null 2>&1 && "
            "gobuster dir -u http://[IP]:[PORT]/ -w /usr/share/wordlists/dirb/common.txt -o [OUTPUT].txt) || "
            "echo feroxbuster/gobuster not found"
        )

        command, outputfile = runtime._build_command(template, "192.168.3.1", "443", "tcp", "web-content-discovery")

        self.assertIn("gobuster -m dir", command)
        self.assertIn("gobuster dir -q -u http://192.168.3.1:443/", command)
        self.assertIn(f"{outputfile}.txt", command)

    def test_build_command_normalizes_legacy_wapiti_template(self):
        from app.web.runtime import WebRuntime

        runtime = WebRuntime.__new__(WebRuntime)
        runtime._require_active_project = lambda: SimpleNamespace(
            properties=SimpleNamespace(runningFolder="/tmp/legion-test-running")
        )

        template = "wapiti https://[IP] -n 10 -b folder -u -v 1 -f txt -o [OUTPUT]"

        command, outputfile = runtime._build_command(template, "192.168.3.100", "443", "tcp", "https-wapiti")

        self.assertIn("wapiti -u https://192.168.3.100:443", command)
        self.assertNotIn(" -u -v ", command)
        self.assertNotIn("wapiti https://192.168.3.100 ", command)
        self.assertIn(outputfile, command)


if __name__ == "__main__":
    unittest.main()
