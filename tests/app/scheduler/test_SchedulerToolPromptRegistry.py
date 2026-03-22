import json
import unittest


class SchedulerToolPromptRegistryTest(unittest.TestCase):
    def test_registry_preserves_web_prompt_group_order(self):
        from app.scheduler.tool_prompt_registry import tool_ids_for_prompt_group

        self.assertEqual(
            ["nuclei-web", "nmap-vuln.nse", "screenshooter"],
            tool_ids_for_prompt_group("web_baseline"),
        )
        self.assertEqual(
            ["whatweb", "whatweb-http", "whatweb-https", "httpx", "nikto", "web-content-discovery", "dirsearch", "ffuf"],
            tool_ids_for_prompt_group("web_deep"),
        )
        self.assertIn("wafw00f", tool_ids_for_prompt_group("web_specialist_followup"))

    def test_candidate_block_includes_prompt_registry_metadata(self):
        from app.scheduler.providers import _build_candidate_block

        block, omitted, visible = _build_candidate_block(
            [
                {
                    "tool_id": "whatweb-http",
                    "label": "Run whatweb (http)",
                    "service_scope": "http",
                    "command_template": "whatweb http://[IP]:[PORT] --color=never",
                }
            ],
            "Prompt prefix\n",
            context={"signals": {"web_service": True}},
            prompt_type="ranking",
        )

        self.assertEqual(0, omitted)
        self.assertEqual(["whatweb-http"], visible)
        payload = json.loads(block.splitlines()[0])
        self.assertIn("fingerprinting", payload["purpose"])
        self.assertEqual("web_url", payload["arg_shape"])
        self.assertTrue(payload["safe_parallel"])
        self.assertIn("deep_web", payload["phase_tags"])
        self.assertIn("follow-up", payload["when_to_use"])

    def test_legacy_smb_nse_tools_have_specific_prompt_metadata(self):
        from app.scheduler.tool_prompt_registry import get_scheduler_tool_prompt_info

        shares_info = get_scheduler_tool_prompt_info(
            "smb-enum-shares",
            label="Enumerate shares (nmap)",
            command_template="nmap -p[PORT] --script=smb-enum-shares [IP]",
            service_scope="microsoft-ds",
        )
        self.assertIn("shares", shares_info.purpose.lower())
        self.assertNotIn("host discovery", shares_info.purpose.lower())
        self.assertEqual("host:port", shares_info.arg_shape)
        self.assertIn("protocol_checks", shares_info.phase_tags)

        rpc_info = get_scheduler_tool_prompt_info(
            "msrpc-enum.nse",
            label="msrpc-enum.nse",
            command_template="nmap -Pn [IP] -p [PORT] --script=msrpc-enum.nse",
            service_scope="msrpc",
        )
        self.assertIn("rpc", rpc_info.purpose.lower())
        self.assertIn("service_fingerprint", rpc_info.phase_tags)

    def test_http_nse_tools_have_specific_prompt_metadata(self):
        from app.scheduler.tool_prompt_registry import get_scheduler_tool_prompt_info

        expected_fragments = {
            "http-errors.nse": "error",
            "http-auth-finder.nse": "auth",
            "http-open-redirect.nse": "redirect",
            "http-ntlm-info.nse": "ntlm",
            "http-git.nse": "git",
            "http-title": "title",
            "http-server-header": "header",
            "http-waf-detect.nse": "waf",
        }

        for tool_id, fragment in expected_fragments.items():
            with self.subTest(tool_id=tool_id):
                info = get_scheduler_tool_prompt_info(
                    tool_id,
                    label=tool_id,
                    command_template=f"nmap -Pn [IP] -p [PORT] --script={tool_id}",
                    service_scope="http",
                )
                self.assertIn(fragment, info.purpose.lower())
                self.assertNotIn("host discovery", info.purpose.lower())
                self.assertEqual("host:port", info.arg_shape)
                self.assertTrue(info.phase_tags)

    def test_unknown_tool_falls_back_to_safe_prompt_metadata(self):
        from app.scheduler.tool_prompt_registry import get_scheduler_tool_prompt_info

        info = get_scheduler_tool_prompt_info(
            "custom-check",
            label="Custom Check",
            command_template="custom-check [IP] [PORT]",
            service_scope="http",
        )

        self.assertEqual("custom-check", info.tool_id)
        self.assertEqual("host:port", info.arg_shape)
        self.assertFalse(info.safe_parallel)
        self.assertEqual((), info.phase_tags)
        self.assertIn("Custom Check", info.purpose)


if __name__ == "__main__":
    unittest.main()
