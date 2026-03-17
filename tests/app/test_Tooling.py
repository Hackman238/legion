import os
import unittest


class ToolingEnvTest(unittest.TestCase):
    def test_build_tool_execution_env_prepends_go_bin_directory(self):
        from app.tooling import build_tool_execution_env

        env = build_tool_execution_env({
            "HOME": "/tmp/legion-home",
            "PATH": "/usr/local/bin:/usr/bin",
            "GOBIN": "",
            "GOPATH": "",
        })

        path_parts = env["PATH"].split(os.pathsep)
        self.assertEqual("/tmp/legion-home/go/bin", path_parts[0])
        self.assertIn("/usr/local/bin", path_parts)
        self.assertIn("/usr/bin", path_parts)

    def test_build_tool_execution_env_prefers_configured_gobin(self):
        from app.tooling import build_tool_execution_env

        env = build_tool_execution_env({
            "HOME": "/tmp/legion-home",
            "PATH": "/usr/bin",
            "GOBIN": "/opt/projectdiscovery/bin",
            "GOPATH": "/workspace/go",
        })

        path_parts = env["PATH"].split(os.pathsep)
        self.assertEqual("/opt/projectdiscovery/bin", path_parts[0])
        self.assertIn("/workspace/go/bin", path_parts)
        self.assertIn("/tmp/legion-home/go/bin", path_parts)


if __name__ == "__main__":
    unittest.main()
