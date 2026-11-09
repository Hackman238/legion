import json
import os
import re
import subprocess
import sys
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
SKILL = os.path.join(REPO, "skills", "legion-mcp")


class LegionMcpSkillTest(unittest.TestCase):
    """The shipped agent skill stays truthful about the MCP server it describes."""

    def _frontmatter(self):
        with open(os.path.join(SKILL, "SKILL.md"), encoding="utf-8") as handle:
            text = handle.read()
        match = re.match(r"^---\n(.*?)\n---\n", text, re.S)
        self.assertIsNotNone(match, "SKILL.md must start with YAML frontmatter")
        return match.group(1), text

    def test_frontmatter_names_the_skill_and_describes_when_to_use_it(self):
        frontmatter, _ = self._frontmatter()
        self.assertIsNotNone(re.search(r"^name: legion-mcp$", frontmatter, re.M), frontmatter)
        self.assertIn("description:", frontmatter)
        for word in ("Legion", "MCP", "legion.py", "nmap"):
            self.assertIn(word, frontmatter)

    def test_every_tool_named_in_the_skill_exists_on_the_server(self):
        from app.mcpServer import MCPServer

        tools = set(MCPServer().tools)
        _, body = self._frontmatter()
        # Tool names on the server all start with one of these verbs; argument names and policy values
        # (host_id, external_recon, node_types) do not, so only real tool references are checked.
        verbs = "list|get|run|start|import|save|open|set|query|export|approve|execute|reject|create|kill"
        named = set(re.findall(r"`((?:%s)_[a-z_]+)`" % verbs, body))
        unknown = sorted(name for name in named if name not in tools)
        self.assertEqual([], unknown)
        for required in ("start_nmap_scan", "get_job", "list_hosts", "run_tool", "list_approvals",
                         "export_report", "save_project"):
            self.assertIn(required, named)

    def test_tools_reference_matches_the_server(self):
        result = subprocess.run(
            [sys.executable, os.path.join(SKILL, "scripts", "generate_tools_reference.py"), "--check"],
            capture_output=True, text=True, cwd=REPO, timeout=120,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_project_links_and_mcp_json_point_at_the_skill_and_the_server(self):
        links = (os.path.join(REPO, ".claude", "skills", "legion-mcp"),
                 os.path.join(REPO, ".agents", "skills", "legion-mcp"))
        for link in links:
            self.assertTrue(os.path.isfile(os.path.join(link, "SKILL.md")), link)
        with open(os.path.join(REPO, ".mcp.json"), encoding="utf-8") as handle:
            config = json.load(handle)
        legion = config["mcpServers"]["legion"]
        self.assertEqual(["legion.py", "--mcp-server"], legion["args"])

    def test_eval_cases_are_well_formed(self):
        evals = os.path.join(SKILL, "evals")
        cases = sorted(entry for entry in os.listdir(evals) if os.path.isdir(os.path.join(evals, entry)))
        self.assertGreaterEqual(len(cases), 3)
        for case in cases:
            self.assertRegex(case, r"^[a-z][a-z0-9-]*$")
            with open(os.path.join(evals, case, "case.yaml"), encoding="utf-8") as handle:
                self.assertIn(f"name: {case}", handle.read())
            with open(os.path.join(evals, case, "prompt.md"), encoding="utf-8") as handle:
                self.assertTrue(handle.read().startswith("---\n"))
            graders = os.listdir(os.path.join(evals, case, "graders"))
            self.assertTrue(graders, case)


if __name__ == "__main__":
    unittest.main()
