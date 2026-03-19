import os
import tempfile
import unittest


class ObservationParsersTest(unittest.TestCase):
    def test_extract_tool_observations_parses_dirsearch_artifact_urls(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        with tempfile.TemporaryDirectory() as tmpdir:
            artifact = os.path.join(tmpdir, "dirsearch.json")
            with open(artifact, "w", encoding="utf-8") as handle:
                handle.write('{"results":[{"status":200,"path":"/admin/"},{"status":403,"path":"/login"}]}')

            parsed = extract_tool_observations(
                "dirsearch",
                "",
                artifact_refs=[artifact],
                port="443",
                protocol="tcp",
                service="https",
                hostname="portal.example",
            )

            urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}
            finding_titles = {str(item.get("title", "")).strip() for item in parsed["findings"]}
            self.assertIn("https://portal.example/admin", urls)
            self.assertIn("https://portal.example/login", urls)
            self.assertIn("Interesting web paths discovered (2)", finding_titles)

    def test_extract_tool_observations_parses_ffuf_json_artifact(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        with tempfile.TemporaryDirectory() as tmpdir:
            artifact = os.path.join(tmpdir, "ffuf.json")
            with open(artifact, "w", encoding="utf-8") as handle:
                handle.write(
                    '{"results":['
                    '{"url":"https://api.example/graphql","status":200},'
                    '{"url":"https://api.example/swagger","status":401}'
                    ']}'
                )

            parsed = extract_tool_observations(
                "ffuf",
                "",
                artifact_refs=[artifact],
                port="443",
                protocol="tcp",
                service="https",
                hostname="api.example",
            )

            urls = {str(item.get("url", "")).strip() for item in parsed["urls"]}
            self.assertIn("https://api.example/graphql", urls)
            self.assertIn("https://api.example/swagger", urls)

    def test_extract_tool_observations_parses_rpcclient_domain_users_and_shares(self):
        from app.scheduler.observation_parsers import extract_tool_observations

        output = (
            "Domain Name: CONTOSO\n"
            "user:[Administrator] rid:[0x1f4]\n"
            "user:[HelpDesk] rid:[0x453]\n"
            "netname: IPC$\n"
            "netname: NETLOGON\n"
        )
        parsed = extract_tool_observations(
            "rpcclient-enum",
            output,
            port="445",
            protocol="tcp",
            service="smb",
            host_ip="10.0.0.5",
        )

        technologies = {str(item.get("name", "")).strip() for item in parsed["technologies"]}
        finding_titles = {str(item.get("title", "")).strip() for item in parsed["findings"]}
        self.assertIn("Active Directory", technologies)
        self.assertIn("SMB domain identified: CONTOSO", finding_titles)
        self.assertIn("SMB users enumerated (2)", finding_titles)
        self.assertIn("SMB shares enumerated (2)", finding_titles)


if __name__ == "__main__":
    unittest.main()
