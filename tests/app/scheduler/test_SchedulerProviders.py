import unittest
from unittest.mock import MagicMock, patch


class SchedulerProvidersTest(unittest.TestCase):
    def setUp(self):
        from app.scheduler.providers import clear_provider_logs

        clear_provider_logs()

    def test_rank_actions_returns_empty_when_provider_disabled(self):
        from app.scheduler.providers import rank_actions_with_provider

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": False,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-5-mini",
                    "api_key": "x",
                }
            },
        }
        ranked = rank_actions_with_provider(config, "external_pentest", "http", "tcp", [])
        self.assertEqual([], ranked)

    def test_ranking_prompt_prioritizes_screenshooter_when_screenshot_gap_is_open(self):
        from app.scheduler.providers import _build_ranking_prompt_package

        candidates = [
            {"tool_id": "banner", "label": "Banner", "command_template": "nc [IP] [PORT]", "service_scope": "http"},
            {"tool_id": "nmap-vuln.nse", "label": "nmap-vuln.nse", "command_template": "nmap --script vuln [IP] -p [PORT]", "service_scope": "http"},
            {"tool_id": "screenshooter", "label": "Capture screenshot", "command_template": "screenshooter [WEB_URL]", "service_scope": "http"},
        ]

        prompt_package = _build_ranking_prompt_package(
            goal_profile="internal_asset_discovery",
            service="http",
            protocol="tcp",
            candidates=candidates,
            context={
                "signals": {"web_service": True},
                "coverage": {
                    "missing": ["missing_screenshot", "missing_nmap_vuln"],
                    "recommended_tool_ids": ["screenshooter", "nmap-vuln.nse"],
                },
                "target": {
                    "host_banners": ["Traccar"] * 8,
                },
            },
        )

        metadata = prompt_package["metadata"]
        self.assertEqual("screenshooter", metadata["visible_candidate_tool_ids"][0])
        self.assertIn(
            "If the remaining coverage gaps cannot be closed by any supplied candidate, return actions as []",
            prompt_package["user_prompt"],
        )

    @patch("app.scheduler.providers.requests.post")
    def test_ranking_prompt_can_disable_context_summary(self, mock_post):
        from app.scheduler.providers import rank_actions_with_provider

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"actions":[{"tool_id":"nuclei-web","score":90,"rationale":"ok"}],'
                            '"host_updates":{"hostname":"","hostname_confidence":0,"os":"","os_confidence":0,"technologies":[]},'
                            '"findings":[],"manual_tests":[],"next_phase":"broad_vuln"}'
                        )
                    }
                }
            ]
        }
        mock_post.return_value = response

        config = {
            "provider": "openai",
            "feature_flags": {
                "context_summary_enabled": False,
            },
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-5-mini",
                    "api_key": "x",
                }
            },
        }
        rank_actions_with_provider(
            config,
            "internal_asset_discovery",
            "http",
            "tcp",
            [{"tool_id": "nuclei-web", "label": "nuclei", "command_template": "nuclei -u [IP]", "service_scope": "http"}],
            context={
                "context_summary": {
                    "confirmed_facts": ["hostname: edge.local"],
                    "important_findings": ["Open admin endpoint [medium]"],
                },
                "target": {"host_ip": "10.0.0.5", "service": "http"},
            },
        )

        prompt = mock_post.call_args.kwargs["json"]["messages"][1]["content"]
        self.assertNotIn('"context_summary"', prompt)
        self.assertIn('"target"', prompt)

    @patch("app.scheduler.providers.requests.post")
    def test_openai_provider_parses_response(self, mock_post):
        from app.scheduler.providers import get_last_provider_payload, rank_actions_with_provider

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"actions":[{"tool_id":"whatweb","score":88,'
                            '"rationale":"Good external fingerprinting signal."}],'
                            '"host_updates":{"hostname":"edge-gateway","hostname_confidence":86,'
                            '"os":"Linux","os_confidence":79,'
                            '"technologies":[{"name":"nginx","version":"1.20","cpe":"cpe:/a:nginx:nginx:1.20","evidence":"Server header"}]},'
                            '"findings":[{"title":"Open admin endpoint","severity":"medium","cvss":5.4,"cve":"","evidence":"/admin/login.jsp"}],'
                            '"manual_tests":[{"why":"Confirm auth controls","command":"curl -k https://10.0.0.5/admin/login.jsp","scope_note":"safe read-only"}],'
                            '"next_phase":"deep_web"}'
                        )
                    }
                }
            ]
        }
        mock_post.return_value = response

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-5-mini",
                    "api_key": "x",
                }
            },
        }
        ranked = rank_actions_with_provider(config, "external_pentest", "http", "tcp", [
            {"tool_id": "whatweb", "label": "whatweb", "command_template": "whatweb [IP]", "service_scope": "http"}
        ])
        self.assertEqual(1, len(ranked))
        self.assertEqual("whatweb", ranked[0]["tool_id"])
        self.assertEqual(88, ranked[0]["score"])
        metadata = get_last_provider_payload(clear=True)
        self.assertEqual("edge-gateway", metadata["host_updates"]["hostname"])
        self.assertEqual("nginx", metadata["technologies"][0]["name"])
        self.assertEqual("Open admin endpoint", metadata["findings"][0]["title"])
        self.assertIn("curl -k", metadata["manual_tests"][0]["command"])
        self.assertEqual("deep_web", metadata["next_phase"])
        self.assertEqual("scheduler-ranking-v2", metadata["prompt_version"])
        self.assertEqual("ranking", metadata["prompt_type"])
        self.assertEqual("web", metadata["prompt_profile"])
        self.assertEqual("initial_discovery", metadata["current_phase"])
        payload = mock_post.call_args.kwargs["json"]
        self.assertIn("Rank only the supplied candidates", payload["messages"][0]["content"])
        self.assertIn("Prompt version: scheduler-ranking-v2", payload["messages"][1]["content"])
        self.assertIn("Prompt profile: web", payload["messages"][1]["content"])
        self.assertIn("max_completion_tokens", payload)
        self.assertNotIn("max_tokens", payload)
        self.assertNotIn("temperature", payload)

    @patch("app.scheduler.providers.requests.post")
    def test_provider_logs_capture_sanitized_request_and_response(self, mock_post):
        from app.scheduler.providers import get_provider_logs, rank_actions_with_provider

        response = MagicMock()
        response.status_code = 200
        response.text = '{"choices":[{"message":{"content":"{\\"actions\\":[{\\"tool_id\\":\\"whatweb\\",\\"score\\":80}]}"}}]}'
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": '{"actions":[{"tool_id":"whatweb","score":80,"rationale":"ok"}]}'
                    }
                }
            ]
        }
        mock_post.return_value = response

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-5-mini",
                    "api_key": "super-secret-token",
                }
            },
        }
        rank_actions_with_provider(
            config,
            "external_pentest",
            "http",
            "tcp",
            [{"tool_id": "whatweb", "label": "whatweb", "command_template": "whatweb [IP]", "service_scope": "http"}],
        )

        logs = get_provider_logs(limit=10)
        self.assertGreaterEqual(len(logs), 1)
        entry = logs[-1]
        self.assertEqual("openai", entry["provider"])
        self.assertEqual("POST", entry["method"])
        self.assertEqual(200, entry["response_status"])
        self.assertIn("***redacted***", entry["request_headers"].get("Authorization", ""))
        self.assertNotIn("super-secret-token", entry["request_body"])
        self.assertEqual("scheduler-ranking-v2", entry["prompt_metadata"].get("prompt_version"))
        self.assertEqual("ranking", entry["prompt_metadata"].get("prompt_type"))
        self.assertEqual("web", entry["prompt_metadata"].get("prompt_profile"))

    @patch("app.scheduler.providers.requests.post")
    def test_openai_provider_uses_structured_outputs_when_enabled(self, mock_post):
        from app.scheduler.providers import get_last_provider_payload, rank_actions_with_provider

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"actions":[{"tool_id":"whatweb","score":87,"rationale":"schema ok"}],'
                            '"host_updates":{"hostname":"","hostname_confidence":0,"os":"","os_confidence":0,"technologies":[]},'
                            '"findings":[],"manual_tests":[],"next_phase":"broad_vuln"}'
                        )
                    }
                }
            ]
        }
        mock_post.return_value = response

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-5-mini",
                    "api_key": "x",
                    "structured_outputs": True,
                }
            },
        }
        ranked = rank_actions_with_provider(
            config,
            "external_pentest",
            "http",
            "tcp",
            [{"tool_id": "whatweb", "label": "whatweb", "command_template": "whatweb [IP]", "service_scope": "http"}],
        )

        self.assertEqual(1, len(ranked))
        payload = mock_post.call_args.kwargs["json"]
        self.assertEqual("json_schema", payload["response_format"]["type"])
        self.assertEqual("scheduler_ranking_response", payload["response_format"]["json_schema"]["name"])
        metadata = get_last_provider_payload(clear=True)
        self.assertTrue(metadata["structured_output_requested"])
        self.assertTrue(metadata["structured_output_used"])
        self.assertFalse(metadata["structured_output_fallback"])

    @patch("app.scheduler.providers.requests.post")
    def test_prompt_profiles_can_be_disabled_via_feature_flag(self, mock_post):
        from app.scheduler.providers import get_last_provider_payload, rank_actions_with_provider

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": '{"actions":[{"tool_id":"whatweb","score":80,"rationale":"ok"}]}'
                    }
                }
            ]
        }
        mock_post.return_value = response

        config = {
            "provider": "openai",
            "feature_flags": {
                "scheduler_prompt_profiles": False,
            },
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-5-mini",
                    "api_key": "x",
                }
            },
        }
        rank_actions_with_provider(
            config,
            "external_pentest",
            "http",
            "tcp",
            [{"tool_id": "whatweb", "label": "whatweb", "command_template": "whatweb [IP]", "service_scope": "http"}],
            context={"coverage": {"missing": ["missing_nmap_vuln"]}},
        )

        payload = mock_post.call_args.kwargs["json"]
        self.assertIn("Prompt profile: generic", payload["messages"][1]["content"])
        self.assertNotIn("Service overlay: web", payload["messages"][1]["content"])
        metadata = get_last_provider_payload(clear=True)
        self.assertEqual("generic", metadata["prompt_profile"])
        self.assertFalse(metadata["service_prompt_overlays_enabled"])

    @patch("app.scheduler.providers.requests.post")
    def test_openai_structured_outputs_fall_back_on_unsupported_parameter(self, mock_post):
        from app.scheduler.providers import get_last_provider_payload, rank_actions_with_provider

        first_response = MagicMock()
        first_response.status_code = 400
        first_response.text = "unsupported response_format json_schema"

        second_response = MagicMock()
        second_response.status_code = 200
        second_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": '{"actions":[{"tool_id":"whatweb","score":84,"rationale":"fallback ok"}]}'
                    }
                }
            ]
        }
        mock_post.side_effect = [first_response, second_response]

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-5-mini",
                    "api_key": "x",
                    "structured_outputs": True,
                }
            },
        }
        ranked = rank_actions_with_provider(
            config,
            "external_pentest",
            "http",
            "tcp",
            [{"tool_id": "whatweb", "label": "whatweb", "command_template": "whatweb [IP]", "service_scope": "http"}],
        )

        self.assertEqual(1, len(ranked))
        self.assertEqual(2, mock_post.call_count)
        first_payload = mock_post.call_args_list[0].kwargs["json"]
        second_payload = mock_post.call_args_list[1].kwargs["json"]
        self.assertIn("response_format", first_payload)
        self.assertNotIn("response_format", second_payload)
        metadata = get_last_provider_payload(clear=True)
        self.assertTrue(metadata["structured_output_requested"])
        self.assertFalse(metadata["structured_output_used"])
        self.assertTrue(metadata["structured_output_fallback"])

    @patch("app.scheduler.providers.requests.post")
    def test_openai_retries_when_response_is_empty_and_length_limited(self, mock_post):
        import copy

        from app.scheduler.providers import rank_actions_with_provider

        first_response = MagicMock()
        first_response.status_code = 200
        first_response.text = '{"choices":[{"message":{"content":""},"finish_reason":"length"}]}'
        first_response.json.return_value = {
            "choices": [
                {
                    "message": {"content": ""},
                    "finish_reason": "length",
                }
            ]
        }

        second_response = MagicMock()
        second_response.status_code = 200
        second_response.text = (
            '{"choices":[{"message":{"content":"{\\"actions\\":[{\\"tool_id\\":\\"whatweb\\",\\"score\\":90}]}"}}]}'
        )
        second_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"actions":[{"tool_id":"whatweb","score":90,'
                            '"rationale":"retry returned usable JSON."}]}'
                        )
                    }
                }
            ]
        }

        captured_payloads = []

        def side_effect(url, headers=None, json=None, timeout=0):
            _ = url, headers, timeout
            captured_payloads.append(copy.deepcopy(json or {}))
            if len(captured_payloads) == 1:
                return first_response
            return second_response

        mock_post.side_effect = side_effect

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-4.1-mini",
                    "api_key": "x",
                }
            },
        }
        ranked = rank_actions_with_provider(
            config,
            "external_pentest",
            "http",
            "tcp",
            [{"tool_id": "whatweb", "label": "whatweb", "command_template": "whatweb [IP]", "service_scope": "http"}],
        )

        self.assertEqual(1, len(ranked))
        self.assertEqual("whatweb", ranked[0]["tool_id"])
        self.assertEqual(2, mock_post.call_count)
        self.assertGreater(
            int(captured_payloads[1]["max_completion_tokens"]),
            int(captured_payloads[0]["max_completion_tokens"]),
        )
        self.assertIn("IMPORTANT RETRY:", captured_payloads[1]["messages"][1]["content"])

    @patch("app.scheduler.providers.requests.post")
    def test_openai_retries_when_response_is_truncated_and_length_limited(self, mock_post):
        import copy

        from app.scheduler.providers import get_provider_logs, rank_actions_with_provider

        first_response = MagicMock()
        first_response.status_code = 200
        first_response.text = (
            '{"choices":[{"message":{"content":"{\\"actions\\":[{\\"tool_id\\":\\"whatweb\\",'
            '\\"score\\":90,\\"rationale\\":\\"partial"},"finish_reason":"length"}]}'
        )
        first_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": '{"actions":[{"tool_id":"whatweb","score":90,"rationale":"partial'
                    },
                    "finish_reason": "length",
                }
            ]
        }

        second_response = MagicMock()
        second_response.status_code = 200
        second_response.text = (
            '{"choices":[{"message":{"content":"{\\"actions\\":[{\\"tool_id\\":\\"whatweb\\",'
            '\\"score\\":91,\\"rationale\\":\\"retried\\"}]}"}}]}'
        )
        second_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"actions":[{"tool_id":"whatweb","score":91,'
                            '"rationale":"retried after truncated response."}]}'
                        )
                    }
                }
            ]
        }

        captured_payloads = []

        def side_effect(url, headers=None, json=None, timeout=0):
            _ = url, headers, timeout
            captured_payloads.append(copy.deepcopy(json or {}))
            if len(captured_payloads) == 1:
                return first_response
            return second_response

        mock_post.side_effect = side_effect

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-4.1-mini",
                    "api_key": "x",
                }
            },
        }
        ranked = rank_actions_with_provider(
            config,
            "external_pentest",
            "http",
            "tcp",
            [{"tool_id": "whatweb", "label": "whatweb", "command_template": "whatweb [IP]", "service_scope": "http"}],
        )

        self.assertEqual(1, len(ranked))
        self.assertEqual("whatweb", ranked[0]["tool_id"])
        self.assertEqual(2, mock_post.call_count)
        self.assertGreater(
            int(captured_payloads[1]["max_completion_tokens"]),
            int(captured_payloads[0]["max_completion_tokens"]),
        )
        self.assertIn("IMPORTANT RETRY:", captured_payloads[1]["messages"][1]["content"])
        logs = get_provider_logs(limit=10)
        self.assertGreaterEqual(len(logs), 2)
        first_meta = logs[-2]["prompt_metadata"]
        second_meta = logs[-1]["prompt_metadata"]
        self.assertEqual(1, first_meta.get("retry_attempt"))
        self.assertEqual("initial_request", first_meta.get("retry_reason"))
        self.assertEqual(
            int(captured_payloads[0]["max_completion_tokens"]),
            int(first_meta.get("effective_max_completion_tokens", 0)),
        )
        self.assertEqual(2, second_meta.get("retry_attempt"))
        self.assertEqual("finish_reason:length", second_meta.get("retry_reason"))
        self.assertEqual(
            int(captured_payloads[1]["max_completion_tokens"]),
            int(second_meta.get("effective_max_completion_tokens", 0)),
        )

    @patch("app.scheduler.providers.requests.post")
    def test_ranking_prompt_overrides_stale_context_summary_phase(self, mock_post):
        from app.scheduler.providers import rank_actions_with_provider

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"actions":[{"tool_id":"nmap-vuln.nse","score":91,"rationale":"ok"}],'
                            '"host_updates":{"hostname":"","hostname_confidence":0,"os":"","os_confidence":0,"technologies":[]},'
                            '"findings":[],"manual_tests":[],"next_phase":"broad_vuln"}'
                        )
                    }
                }
            ]
        }
        mock_post.return_value = response

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-4.1-mini",
                    "api_key": "x",
                }
            },
        }
        rank_actions_with_provider(
            config,
            "internal_asset_discovery",
            "http",
            "tcp",
            [{"tool_id": "nmap-vuln.nse", "label": "nmap-vuln.nse", "command_template": "nmap [IP]", "service_scope": "http"}],
            context={
                "coverage": {"missing": ["missing_nmap_vuln"]},
                "context_summary": {
                    "focus": {
                        "analysis_mode": "standard",
                        "service": "http",
                        "current_phase": "complete",
                    }
                },
            },
        )

        payload = mock_post.call_args.kwargs["json"]
        prompt = payload["messages"][1]["content"]
        self.assertIn('"current_phase":"broad_vuln"', prompt)
        self.assertNotIn('"current_phase":"complete"', prompt)

    @patch("app.scheduler.providers.requests.post")
    def test_provider_payload_filters_missing_tool_manual_tests_sanitizes_versions_and_clamps_next_phase(self, mock_post):
        from app.scheduler.providers import get_last_provider_payload, rank_actions_with_provider

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"actions":[{"tool_id":"banner","score":82,"rationale":"ok"}],'
                            '"host_updates":{"hostname":"unifi.local","hostname_confidence":90,"os":"unknown","os_confidence":20,'
                            '"technologies":['
                            '{"name":"nginx","version":"7.80","cpe":"cpe:/a:nginx:nginx:7.80","evidence":"http-headers.nse output fingerprint"},'
                            '{"name":"Apache HTTP Server","version":"7.80","cpe":"cpe:/a:apache:http_server:7.80","evidence":"http-vuln-cve2011-3192.nse output fingerprint"}'
                            ']},'
                            '"findings":[],'
                            '"manual_tests":['
                            '{"why":"bad","command":"dirsearch -u http://unifi.local -e php","scope_note":"skip"},'
                            '{"why":"check availability","command":"which whatweb","scope_note":"allowed"}'
                            '],'
                            '"next_phase":"broad_vuln"}'
                        )
                    }
                }
            ]
        }
        mock_post.return_value = response

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-4.1-mini",
                    "api_key": "x",
                }
            },
        }
        ranked = rank_actions_with_provider(
            config,
            "internal_asset_discovery",
            "http",
            "tcp",
            [{"tool_id": "banner", "label": "Grab banner", "command_template": "nc [IP] [PORT]", "service_scope": "http"}],
            context={
                "signals": {
                    "web_service": True,
                    "missing_tools": ["dirsearch", "whatweb-http"],
                },
                "coverage": {
                    "stage": "baseline",
                    "missing": ["missing_nikto"],
                },
            },
        )

        self.assertEqual("banner", ranked[0]["tool_id"])
        payload = get_last_provider_payload(clear=True)
        self.assertEqual("deep_web", payload["current_phase"])
        self.assertEqual("deep_web", payload["next_phase"])
        self.assertEqual(1, len(payload["manual_tests"]))
        self.assertEqual("which whatweb", payload["manual_tests"][0]["command"])

        tech_by_name = {
            str(item.get("name", "")).strip().lower(): item
            for item in payload["technologies"]
        }
        self.assertEqual("", str(tech_by_name["nginx"]["version"]))
        self.assertEqual("cpe:/a:nginx:nginx", str(tech_by_name["nginx"]["cpe"]))
        self.assertEqual("", str(tech_by_name["apache http server"]["version"]))
        self.assertEqual("cpe:/a:apache:http_server", str(tech_by_name["apache http server"]["cpe"]))

    @patch("app.scheduler.providers.requests.post")
    def test_provider_payload_filters_manual_tests_for_audited_missing_tools(self, mock_post):
        from app.scheduler.providers import get_last_provider_payload, rank_actions_with_provider

        response = MagicMock()
        response.status_code = 200
        response.text = (
            '{"choices":[{"message":{"content":"'
            '{\\"actions\\":[{\\"tool_id\\":\\"banner\\",\\"score\\":82,\\"rationale\\":\\"ok\\"}],'
            '\\"host_updates\\":{\\"hostname\\":\\"unifi.local\\",\\"hostname_confidence\\":90,\\"os\\":\\"unknown\\",\\"os_confidence\\":20,\\"technologies\\":[]},'
            '\\"findings\\":[],'
            '\\"manual_tests\\":['
            '{\\"why\\":\\"scan\\",\\"command\\":\\"nikto -host https://192.168.3.1:443\\",\\"scope_note\\":\\"skip\\"},'
            '{\\"why\\":\\"headers\\",\\"command\\":\\"curl -k -I https://192.168.3.1:443\\",\\"scope_note\\":\\"keep\\"}'
            '],'
            '\\"next_phase\\":\\"deep_web\\"'
            '"}}]}'
        )
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"actions":[{"tool_id":"banner","score":82,"rationale":"ok"}],'
                            '"host_updates":{"hostname":"unifi.local","hostname_confidence":90,"os":"unknown","os_confidence":20,"technologies":[]},'
                            '"findings":[],'
                            '"manual_tests":['
                            '{"why":"scan","command":"nikto -host https://192.168.3.1:443","scope_note":"skip"},'
                            '{"why":"headers","command":"curl -k -I https://192.168.3.1:443","scope_note":"keep"}'
                            '],'
                            '"next_phase":"deep_web"}'
                        )
                    }
                }
            ]
        }
        mock_post.return_value = response

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-4.1-mini",
                    "api_key": "x",
                }
            },
        }
        ranked = rank_actions_with_provider(
            config,
            "internal_asset_discovery",
            "http",
            "tcp",
            [{"tool_id": "banner", "label": "Grab banner", "command_template": "nc [IP] [PORT]", "service_scope": "http"}],
            context={
                "signals": {
                    "web_service": True,
                },
                "tool_audit": {
                    "available_tool_ids": ["curl"],
                    "unavailable_tool_ids": ["nikto"],
                },
            },
        )

        self.assertEqual("banner", ranked[0]["tool_id"])
        payload = get_last_provider_payload(clear=True)
        self.assertEqual(1, len(payload["manual_tests"]))
        self.assertEqual("curl -k -I https://192.168.3.1:443", payload["manual_tests"][0]["command"])

    @patch("app.scheduler.providers.requests.post")
    def test_provider_payload_does_not_treat_finished_wrapper_commands_as_unavailable(self, mock_post):
        from app.scheduler.providers import get_last_provider_payload, rank_actions_with_provider

        response = MagicMock()
        response.status_code = 200
        response.text = (
            '{"choices":[{"message":{"content":"'
            '{\\"actions\\":[{\\"tool_id\\":\\"banner\\",\\"score\\":80,\\"rationale\\":\\"ok\\"}],'
            '\\"host_updates\\":{\\"hostname\\":\\"unifi.local\\",\\"hostname_confidence\\":90,\\"os\\":\\"unknown\\",\\"os_confidence\\":20,\\"technologies\\":[]},'
            '\\"findings\\":[],'
            '\\"manual_tests\\":['
            '{\\"why\\":\\"fingerprint\\",\\"command\\":\\"whatweb http://192.168.3.1:80\\",\\"scope_note\\":\\"keep\\"}'
            '],'
            '\\"next_phase\\":\\"deep_web\\"'
            '"}}]}'
        )
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"actions":[{"tool_id":"banner","score":80,"rationale":"ok"}],'
                            '"host_updates":{"hostname":"unifi.local","hostname_confidence":90,"os":"unknown","os_confidence":20,"technologies":[]},'
                            '"findings":[],'
                            '"manual_tests":[{"why":"fingerprint","command":"whatweb http://192.168.3.1:80","scope_note":"keep"}],'
                            '"next_phase":"deep_web"}'
                        )
                    }
                }
            ]
        }
        mock_post.return_value = response

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-4.1-mini",
                    "api_key": "x",
                }
            },
        }
        ranked = rank_actions_with_provider(
            config,
            "internal_asset_discovery",
            "http",
            "tcp",
            [{"tool_id": "banner", "label": "Grab banner", "command_template": "nc [IP] [PORT]", "service_scope": "http"}],
            context={
                "recent_processes": [
                    {
                        "tool_id": "whatweb-http",
                        "status": "Finished",
                        "command_excerpt": "(command -v whatweb >/dev/null 2>&1 && whatweb http://unifi.local:8080 --color=never) || echo whatweb not found",
                        "output_excerpt": "http://unifi.local:8080 [400 Bad Request] nginx, HTML5",
                    }
                ],
            },
        )

        self.assertEqual("banner", ranked[0]["tool_id"])
        payload = get_last_provider_payload(clear=True)
        self.assertEqual(1, len(payload["manual_tests"]))
        self.assertEqual("whatweb http://192.168.3.1:80", payload["manual_tests"][0]["command"])

    @patch("app.scheduler.providers.requests.post")
    def test_test_provider_connection_retries_on_openai_length_empty(self, mock_post):
        from app.scheduler.providers import test_provider_connection

        first_response = MagicMock()
        first_response.status_code = 200
        first_response.text = '{"choices":[{"message":{"content":""},"finish_reason":"length"}]}'
        first_response.json.return_value = {
            "choices": [
                {
                    "message": {"content": ""},
                    "finish_reason": "length",
                }
            ]
        }

        second_response = MagicMock()
        second_response.status_code = 200
        second_response.text = (
            '{"choices":[{"message":{"content":"{\\"actions\\":[{\\"tool_id\\":\\"healthcheck\\",\\"score\\":100}]}"}}]}'
        )
        second_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"actions":[{"tool_id":"healthcheck","score":100,'
                            '"rationale":"ok"}]}'
                        )
                    }
                }
            ]
        }

        mock_post.side_effect = [first_response, second_response]

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-4.1-mini",
                    "api_key": "x",
                }
            },
        }
        result = test_provider_connection(config)
        self.assertTrue(result["ok"])
        self.assertEqual("openai", result["provider"])
        self.assertEqual(2, mock_post.call_count)
        self.assertFalse(result["structured_output_requested"])
        self.assertFalse(result["structured_output_used"])
        self.assertFalse(result["structured_output_fallback"])

    @patch("app.scheduler.providers.requests.post")
    def test_test_provider_connection_uses_structured_outputs_when_enabled(self, mock_post):
        from app.scheduler.providers import test_provider_connection

        response = MagicMock()
        response.status_code = 200
        response.text = (
            '{"choices":[{"message":{"content":"{\\"actions\\":[{\\"tool_id\\":\\"healthcheck\\",\\"score\\":100}]}"}}]}'
        )
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": '{"actions":[{"tool_id":"healthcheck","score":100,"rationale":"ok"}]}'
                    }
                }
            ]
        }
        mock_post.return_value = response

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-4.1-mini",
                    "api_key": "x",
                    "structured_outputs": True,
                }
            },
        }
        result = test_provider_connection(config)
        self.assertTrue(result["ok"])
        payload = mock_post.call_args.kwargs["json"]
        self.assertIn("response_format", payload)
        self.assertEqual("json_schema", payload["response_format"]["type"])
        self.assertTrue(result["structured_output_requested"])
        self.assertTrue(result["structured_output_used"])
        self.assertFalse(result["structured_output_fallback"])

    @patch("app.scheduler.providers.requests.post")
    def test_test_provider_connection_falls_back_when_structured_outputs_are_rejected(self, mock_post):
        from app.scheduler.providers import test_provider_connection

        first_response = MagicMock()
        first_response.status_code = 400
        first_response.text = "unsupported response_format json_schema"

        second_response = MagicMock()
        second_response.status_code = 200
        second_response.text = (
            '{"choices":[{"message":{"content":"{\\"actions\\":[{\\"tool_id\\":\\"healthcheck\\",\\"score\\":100}]}"}}]}'
        )
        second_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": '{"actions":[{"tool_id":"healthcheck","score":100,"rationale":"ok"}]}'
                    }
                }
            ]
        }
        mock_post.side_effect = [first_response, second_response]

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-4.1-mini",
                    "api_key": "x",
                    "structured_outputs": True,
                }
            },
        }
        result = test_provider_connection(config)
        self.assertTrue(result["ok"])
        self.assertEqual(2, mock_post.call_count)
        first_payload = mock_post.call_args_list[0].kwargs["json"]
        second_payload = mock_post.call_args_list[1].kwargs["json"]
        self.assertIn("response_format", first_payload)
        self.assertNotIn("response_format", second_payload)
        self.assertTrue(result["structured_output_requested"])
        self.assertFalse(result["structured_output_used"])
        self.assertTrue(result["structured_output_fallback"])

    @patch("app.scheduler.providers.requests.post")
    def test_claude_provider_parses_text_block(self, mock_post):
        from app.scheduler.providers import rank_actions_with_provider

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "content": [
                {
                    "type": "text",
                    "text": '{"actions":[{"tool_id":"nikto","score":73,"rationale":"Useful web baseline."}]}',
                }
            ]
        }
        mock_post.return_value = response

        config = {
            "provider": "claude",
            "providers": {
                "claude": {
                    "enabled": True,
                    "base_url": "https://api.anthropic.com",
                    "model": "claude-3-7-sonnet-latest",
                    "api_key": "x",
                }
            },
        }
        ranked = rank_actions_with_provider(config, "external_pentest", "http", "tcp", [
            {"tool_id": "nikto", "label": "nikto", "command_template": "nikto -h [IP]", "service_scope": "http"}
        ])
        self.assertEqual(1, len(ranked))
        self.assertEqual("nikto", ranked[0]["tool_id"])
        payload = mock_post.call_args.kwargs["json"]
        self.assertIn("system", payload)
        self.assertIn("Rank only the supplied candidates", payload["system"])
        self.assertIn("Prompt profile: web", payload["messages"][0]["content"])

    @patch("app.scheduler.providers.requests.post")
    def test_openai_reflection_provider_parses_response(self, mock_post):
        from app.scheduler.providers import get_provider_logs, reflect_on_scheduler_progress

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"state":"stalled","reason":"Coverage has plateaued.",'
                            '"priority_shift":"manual_validation",'
                            '"promote_tool_ids":["whatweb"],'
                            '"suppress_tool_ids":["nikto"],'
                            '"manual_tests":[{"why":"validate auth manually","command":"curl -k https://10.0.0.5/admin","scope_note":"safe"}]}'
                        )
                    }
                }
            ]
        }
        mock_post.return_value = response

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-5-mini",
                    "api_key": "x",
                }
            },
        }
        payload = reflect_on_scheduler_progress(
            config,
            "external_pentest",
            "https",
            "tcp",
            context={
                "coverage": {"stage": "baseline", "missing": ["missing_nmap_vuln"]},
                "signals": {"web_service": True, "tls_detected": True},
            },
            recent_rounds=[
                {"round": 1, "decision_tool_ids": ["nuclei-web"], "coverage_missing": ["missing_nmap_vuln"], "progress_score": 0},
                {"round": 2, "decision_tool_ids": ["nikto"], "coverage_missing": ["missing_nmap_vuln"], "progress_score": 0},
            ],
            trigger_reason="phase_transition",
            trigger_context={
                "reason": "phase_transition",
                "round_number": 3,
                "previous_phase": "service_fingerprint",
                "current_phase": "broad_vuln",
            },
        )

        self.assertEqual("stalled", payload["state"])
        self.assertEqual("manual_validation", payload["priority_shift"])
        self.assertEqual(["whatweb"], payload["promote_tool_ids"])
        self.assertEqual(["nikto"], payload["suppress_tool_ids"])
        self.assertIn("curl -k", payload["manual_tests"][0]["command"])
        self.assertEqual("phase_transition", payload["trigger_reason"])
        request_payload = mock_post.call_args.kwargs["json"]
        self.assertIn("Assess whether recent rounds are still productive", request_payload["messages"][0]["content"])
        self.assertIn("Prompt version: scheduler-reflection-v1", request_payload["messages"][1]["content"])
        self.assertIn("Reflection trigger:", request_payload["messages"][1]["content"])
        self.assertIn('"previous_phase":"service_fingerprint"', request_payload["messages"][1]["content"])
        self.assertIn("Recent rounds:", request_payload["messages"][1]["content"])
        logs = get_provider_logs(limit=10)
        self.assertEqual("reflection", logs[-1]["prompt_metadata"].get("prompt_type"))
        self.assertEqual("scheduler-reflection-v1", logs[-1]["prompt_metadata"].get("prompt_version"))
        self.assertEqual("phase_transition", logs[-1]["prompt_metadata"].get("trigger_reason"))

    @patch("app.scheduler.providers.requests.post")
    def test_openai_web_followup_sidecar_parses_response(self, mock_post):
        from app.scheduler.providers import select_web_followup_with_provider

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"focus":"content_discovery",'
                            '"selected_tool_ids":["dirsearch","curl-headers"],'
                            '"reason":"Reflection and findings point to bounded content discovery plus header validation.",'
                            '"manual_tests":[{"why":"Validate exposed path safely","command":"curl -k https://10.0.0.5/admin","scope_note":"safe read-only"}]}'
                        )
                    }
                }
            ]
        }
        mock_post.return_value = response

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-5-mini",
                    "api_key": "x",
                }
            },
        }
        payload = select_web_followup_with_provider(
            config,
            "external_pentest",
            "http",
            "tcp",
            [
                {"tool_id": "dirsearch", "label": "Dirsearch", "command_template": "dirsearch -u https://[IP]:[PORT]", "service_scope": "http"},
                {"tool_id": "curl-headers", "label": "cURL headers", "command_template": "curl -k -I https://[IP]:[PORT]", "service_scope": "http"},
            ],
            context={
                "signals": {"web_service": True, "vuln_hits": 1},
                "coverage": {"missing": ["missing_followup_after_vuln"]},
                "context_summary": {
                    "reflection_posture": {
                        "state": "stalled",
                        "priority_shift": "targeted_followup",
                        "reason": "Baseline completed; validate suspicious paths.",
                    }
                },
            },
        )

        self.assertEqual("content_discovery", payload["focus"])
        self.assertEqual(["dirsearch", "curl-headers"], payload["selected_tool_ids"])
        self.assertIn("bounded content discovery", payload["reason"])
        self.assertEqual("scheduler-web-followup-v1", payload["prompt_version"])
        self.assertEqual("web_followup", payload["prompt_type"])
        self.assertEqual("targeted_checks", payload["current_phase"])
        self.assertIn("curl -k", payload["manual_tests"][0]["command"])
        request_payload = mock_post.call_args.kwargs["json"]
        self.assertIn("specialist web follow-up advisor", request_payload["messages"][0]["content"])
        self.assertIn("Prompt version: scheduler-web-followup-v1", request_payload["messages"][1]["content"])
        self.assertIn("selected_tool_ids", request_payload["messages"][1]["content"])
        self.assertGreaterEqual(int(request_payload["max_completion_tokens"]), 320)

    @patch("app.scheduler.providers.requests.post")
    def test_claude_web_followup_sidecar_parses_text_block(self, mock_post):
        from app.scheduler.providers import select_web_followup_with_provider

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "content": [
                {
                    "type": "text",
                    "text": (
                        '{"focus":"vuln_followup",'
                        '"selected_tool_ids":["nuclei-cves"],'
                        '"reason":"Observed findings warrant targeted nuclei follow-up.",'
                        '"manual_tests":[]}'
                    ),
                }
            ]
        }
        mock_post.return_value = response

        config = {
            "provider": "claude",
            "providers": {
                "claude": {
                    "enabled": True,
                    "base_url": "https://api.anthropic.com",
                    "model": "claude-3-7-sonnet-latest",
                    "api_key": "x",
                }
            },
        }
        payload = select_web_followup_with_provider(
            config,
            "external_pentest",
            "https",
            "tcp",
            [{"tool_id": "nuclei-cves", "label": "nuclei CVEs", "command_template": "nuclei -u https://[IP]:[PORT] -tags cves", "service_scope": "https"}],
            context={"signals": {"web_service": True, "vuln_hits": 1}, "coverage": {"missing": ["missing_cpe_cve_enrichment"]}},
        )

        self.assertEqual("vuln_followup", payload["focus"])
        self.assertEqual(["nuclei-cves"], payload["selected_tool_ids"])
        self.assertEqual("scheduler-web-followup-v1", payload["prompt_version"])
        request_payload = mock_post.call_args.kwargs["json"]
        self.assertIn("specialist web follow-up advisor", request_payload["system"])
        self.assertIn("Prompt version: scheduler-web-followup-v1", request_payload["messages"][0]["content"])

    @patch("app.scheduler.providers.requests.post")
    @patch("app.scheduler.providers.requests.get")
    def test_lm_studio_provider_auto_discovers_model(self, mock_get, mock_post):
        from app.scheduler.providers import rank_actions_with_provider

        models_response = MagicMock()
        models_response.status_code = 200
        models_response.json.return_value = {
            "data": [
                {"id": "tinyllama-1.1b"},
                {"id": "o3-7b-instruct"},
            ]
        }
        mock_get.return_value = models_response

        completion_response = MagicMock()
        completion_response.status_code = 200
        completion_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"actions":[{"tool_id":"whatweb","score":91,'
                            '"rationale":"Good external fingerprinting signal."}]}'
                        )
                    }
                }
            ]
        }
        mock_post.return_value = completion_response

        config = {
            "provider": "lm_studio",
            "providers": {
                "lm_studio": {
                    "enabled": True,
                    "base_url": "http://127.0.0.1:1234/v1",
                    "model": "",
                    "api_key": "",
                }
            },
        }
        ranked = rank_actions_with_provider(config, "external_pentest", "http", "tcp", [
            {"tool_id": "whatweb", "label": "whatweb", "command_template": "whatweb [IP]", "service_scope": "http"}
        ])
        self.assertEqual(1, len(ranked))
        self.assertEqual("whatweb", ranked[0]["tool_id"])
        self.assertEqual(91, ranked[0]["score"])

        payload = mock_post.call_args.kwargs["json"]
        self.assertEqual("o3-7b-instruct", payload["model"])

    @patch("app.scheduler.providers.requests.post")
    def test_lm_studio_falls_back_to_native_chat_endpoint(self, mock_post):
        from app.scheduler.providers import rank_actions_with_provider

        def post_side_effect(url, headers=None, json=None, timeout=0):
            if url.endswith("/chat/completions"):
                response = MagicMock()
                response.status_code = 404
                response.text = "not found"
                return response
            if url.endswith("/api/v1/chat"):
                response = MagicMock()
                response.status_code = 200
                response.json.return_value = {
                    "output": [
                        {"type": "reasoning", "content": "thinking"},
                        {
                            "type": "message",
                            "content": (
                                '{"actions":[{"tool_id":"whatweb","score":86,'
                                '"rationale":"Native endpoint worked."}]}'
                            ),
                        },
                    ]
                }
                return response
            raise AssertionError(f"Unexpected URL: {url}")

        mock_post.side_effect = post_side_effect

        config = {
            "provider": "lm_studio",
            "providers": {
                "lm_studio": {
                    "enabled": True,
                    "base_url": "http://127.0.0.1:1234/v1",
                    "model": "openai/gpt-oss-20b",
                    "api_key": "",
                }
            },
        }

        ranked = rank_actions_with_provider(
            config,
            "external_pentest",
            "http",
            "tcp",
            [{"tool_id": "whatweb", "label": "whatweb", "command_template": "whatweb [IP]", "service_scope": "http"}],
        )
        self.assertEqual(1, len(ranked))
        self.assertEqual("whatweb", ranked[0]["tool_id"])
        self.assertEqual(86, ranked[0]["score"])

    @patch("app.scheduler.providers.requests.post")
    def test_prompt_is_bounded_for_context_limited_models(self, mock_post):
        from app.scheduler.providers import rank_actions_with_provider

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"actions":[{"tool_id":"tool-0","score":81,'
                            '"rationale":"bounded prompt test"}]}'
                        )
                    }
                }
            ]
        }
        mock_post.return_value = response

        candidates = []
        for i in range(200):
            candidates.append({
                "tool_id": f"tool-{i}",
                "label": f"Tool Label {i}",
                "command_template": "very-long-command " + ("x" * 500),
                "service_scope": "http",
            })

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-5-mini",
                    "api_key": "x",
                }
            },
        }
        rank_actions_with_provider(config, "external_pentest", "http", "tcp", candidates)
        payload = mock_post.call_args.kwargs["json"]
        prompt = payload["messages"][1]["content"]
        self.assertLessEqual(len(prompt), 5400)
        self.assertIn("omitted due to context budget", prompt)
        self.assertIn("Prompt version: scheduler-ranking-v2", prompt)

    @patch("app.scheduler.providers.requests.post")
    def test_ranking_schema_and_parser_stay_with_visible_candidates_only(self, mock_post):
        from app.scheduler.providers import get_last_provider_payload, rank_actions_with_provider

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"actions":['
                            '{"tool_id":"tool-0","score":91,"rationale":"visible candidate"},'
                            '{"tool_id":"tool-39","score":99,"rationale":"should be rejected"}'
                            '],"host_updates":{"hostname":"","hostname_confidence":0,"os":"","os_confidence":0,"technologies":[]},'
                            '"findings":[],"manual_tests":[],"next_phase":"service_fingerprint"}'
                        )
                    }
                }
            ]
        }
        mock_post.return_value = response

        candidates = []
        for i in range(40):
            candidates.append({
                "tool_id": f"tool-{i}",
                "label": f"Tool Label {i}",
                "command_template": "very-long-command " + ("x" * 500),
                "service_scope": "http",
            })

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-4.1-mini",
                    "api_key": "x",
                    "structured_outputs": True,
                }
            },
        }

        ranked = rank_actions_with_provider(config, "external_pentest", "http", "tcp", candidates)

        self.assertEqual([{"tool_id": "tool-0", "score": 91.0, "rationale": "visible candidate"}], ranked)
        payload = mock_post.call_args.kwargs["json"]
        enum_values = payload["response_format"]["json_schema"]["schema"]["properties"]["actions"]["items"]["properties"]["tool_id"]["enum"]
        self.assertIn("tool-0", enum_values)
        self.assertNotIn("tool-39", enum_values)
        metadata = get_last_provider_payload(clear=True)
        self.assertLess(metadata["visible_candidate_count"], len(candidates))
        self.assertIn("tool-39", metadata["rejected_action_tool_ids"])

    @patch("app.scheduler.providers.requests.post")
    def test_prompt_includes_context_signals(self, mock_post):
        from app.scheduler.providers import rank_actions_with_provider

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"actions":[{"tool_id":"nuclei-web","score":92,'
                            '"rationale":"context-aware ranking"}]}'
                        )
                    }
                }
            ]
        }
        mock_post.return_value = response

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-5-mini",
                    "api_key": "x",
                }
            },
        }
        rank_actions_with_provider(
            config,
            "external_pentest",
            "http",
            "tcp",
            [{"tool_id": "nuclei-web", "label": "nuclei", "command_template": "nuclei -u [IP]", "service_scope": "http"}],
            context={
                "context_summary": {
                    "focus": {
                        "analysis_mode": "dig_deeper",
                        "service": "http",
                        "coverage_stage": "baseline",
                        "current_phase": "targeted_checks",
                    },
                    "coverage_missing": ["missing_nmap_vuln", "missing_nuclei_auto"],
                    "recommended_tools": ["nmap-vuln.nse", "nuclei-web"],
                    "active_signals": ["web_service", "tls_detected"],
                    "known_technologies": ["Jetty 10.0.13", "nginx 1.20"],
                    "top_findings": ["Open admin endpoint [medium]"],
                    "recent_attempts": ["banner", "whatweb"],
                    "recent_failures": ["feroxbuster: command not found"],
                    "manual_tests": ["curl -k https://10.0.0.5/admin"],
                    "reflection_posture": {
                        "state": "stalled",
                        "priority_shift": "manual_validation",
                        "reason": "Coverage plateaued",
                        "suppress_tool_ids": ["nikto"],
                        "promote_tool_ids": ["whatweb"],
                    },
                },
                "target": {
                    "host_ip": "10.0.0.5",
                    "hostname": "unknown",
                    "service": "http",
                    "service_product": "nginx",
                    "host_open_services": ["http", "https"],
                    "host_open_ports": ["80/tcp:http", "443/tcp:https"],
                    "host_banners": ["80/tcp:UniFi OS", "443/tcp:nginx 1.20"],
                },
                "host_ports": [
                    {
                        "port": "80",
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "service_product": "nginx",
                        "service_extrainfo": "UniFi OS",
                        "banner": "UniFi OS",
                        "scripts": ["http-title", "http-enum.nse"],
                    }
                ],
                "inferred_technologies": [
                    {"name": "Jetty", "version": "10.0.13", "cpe": "cpe:/a:eclipse:jetty:10.0.13", "evidence": "service 8082/tcp"},
                ],
                "host_cves": [
                    {"name": "CVE-2025-9999", "severity": "high", "product": "nginx", "version": "1.20"},
                ],
                "signals": {"tls_detected": True, "vuln_hits": 2, "wordpress_detected": False},
                "attempted_tool_ids": ["banner"],
                "coverage": {
                    "analysis_mode": "dig_deeper",
                    "stage": "baseline",
                    "missing": ["missing_nmap_vuln", "missing_nuclei_auto"],
                    "recommended_tool_ids": ["nmap-vuln.nse", "nuclei-web"],
                    "has": {"discovery": True, "nmap_vuln": False, "nuclei_auto": False},
                },
                "scripts": [{"script_id": "ssl-cert", "port": "443", "protocol": "tcp", "excerpt": "CN=portal.local"}],
                "recent_processes": [{
                    "tool_id": "whatweb",
                    "status": "Finished",
                    "port": "80",
                    "protocol": "tcp",
                    "command_excerpt": "whatweb 10.0.0.5:80",
                    "output_excerpt": "Apache, jQuery",
                }],
                "host_ai_state": {
                    "provider": "openai",
                    "goal_profile": "internal_asset_discovery",
                    "next_phase": "targeted_checks",
                    "host_updates": {"hostname": "edge.local", "os": "linux"},
                    "technologies": [{"name": "nginx", "version": "1.20", "cpe": "cpe:/a:nginx:nginx:1.20", "evidence": "server header"}],
                    "findings": [{"title": "Open admin endpoint", "severity": "medium", "cve": "", "evidence": "/admin"}],
                    "manual_tests": [{"why": "validate auth", "command": "curl -k https://10.0.0.5/admin", "scope_note": "safe"}],
                    "reflection": {
                        "state": "stalled",
                        "priority_shift": "manual_validation",
                        "reason": "Coverage plateaued",
                        "promote_tool_ids": ["whatweb"],
                        "suppress_tool_ids": ["nikto"],
                    },
                },
            },
        )
        payload = mock_post.call_args.kwargs["json"]
        prompt = payload["messages"][1]["content"]
        self.assertIn("Context:", prompt)
        self.assertIn("context_summary", prompt)
        self.assertLess(prompt.index('{"context_summary"'), prompt.index('{"target"'))
        self.assertIn("Current phase:", prompt)
        self.assertIn("Prompt profile: web:broad_vuln", prompt)
        self.assertIn("tls_detected", prompt)
        self.assertIn("wordpress_detected", prompt)
        self.assertIn("false", prompt.lower())
        self.assertIn("attempted_tools", prompt)
        self.assertIn("host_ports", prompt)
        self.assertIn("UniFi OS", prompt)
        self.assertIn("whatweb", prompt)
        self.assertIn("host_ai_state", prompt)
        self.assertIn("Open admin endpoint", prompt)
        self.assertIn("manual_tests", prompt)
        self.assertIn("reflection", prompt)
        self.assertIn("manual_validation", prompt)
        self.assertIn("feroxbuster: command not found", prompt)
        self.assertIn("coverage", prompt)
        self.assertIn("missing_nmap_vuln", prompt)
        self.assertIn("host_cves", prompt)
        self.assertIn("inferred_technologies", prompt)
        self.assertIn("jetty", prompt.lower())
        metadata = mock_post.call_args.kwargs["json"]["messages"][0]["content"]
        self.assertIn("Prefer closing baseline coverage gaps", metadata)

    def test_ranking_prompt_keeps_multiple_visible_candidates_under_large_context(self):
        from app.scheduler.providers import _build_candidate_block

        candidates = []
        for i in range(12):
            candidates.append({
                "tool_id": f"tool-{i}",
                "label": f"Tool Label {i}",
                "command_template": "very-long-command " + ("x" * 500),
                "service_scope": "http,https,ssl",
            })

        block, omitted, visible = _build_candidate_block(
            candidates,
            "x" * 11000,
            context={
                "coverage": {
                    "missing": ["missing_nmap_vuln", "missing_nuclei_auto"],
                    "recommended_tool_ids": ["tool-0", "tool-1", "tool-2"],
                },
                "signals": {"web_service": True},
            },
            prompt_type="ranking",
        )

        self.assertTrue(block)
        self.assertGreaterEqual(len(visible), 4)
        self.assertLessEqual(len(visible), len(candidates))
        self.assertGreaterEqual(omitted, 0)

    @patch("app.scheduler.providers.requests.post")
    def test_web_followup_filters_selected_tools_to_visible_candidates_under_budget_pressure(self, mock_post):
        from app.scheduler.providers import select_web_followup_with_provider

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"focus":"coverage_gap",'
                            '"selected_tool_ids":["tool-0","tool-11"],'
                            '"reason":"pick the visible and omitted candidates",'
                            '"manual_tests":[]}'
                        )
                    }
                }
            ]
        }
        mock_post.return_value = response

        candidates = []
        for i in range(12):
            candidates.append({
                "tool_id": f"tool-{i}",
                "label": f"Tool Label {i}",
                "command_template": "tool-runner " + ("x" * 500),
                "service_scope": "http",
            })

        config = {
            "provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "base_url": "https://api.openai.com/v1",
                    "model": "gpt-5-mini",
                    "api_key": "x",
                }
            },
        }
        payload = select_web_followup_with_provider(
            config,
            "internal_asset_discovery",
            "http",
            "tcp",
            candidates,
            context={
                "context_summary": {
                    "confirmed_facts": [" | ".join(f"fact-{i}" for i in range(1200))],
                    "missing_coverage": ["missing_nmap_vuln", "missing_nuclei_auto"],
                },
                "coverage": {
                    "missing": ["missing_nmap_vuln", "missing_nuclei_auto"],
                    "recommended_tool_ids": ["tool-0", "tool-1", "tool-2", "tool-3"],
                },
                "signals": {"web_service": True},
            },
        )

        self.assertGreaterEqual(payload["visible_candidate_count"], 4)
        self.assertLess(payload["visible_candidate_count"], len(candidates))
        self.assertNotIn("tool-11", list(payload.get("visible_candidate_tool_ids", []) or []))
        self.assertEqual(["tool-0"], payload["selected_tool_ids"])

    def test_determine_phase_uses_cpe_cve_enrichment_gap(self):
        from app.scheduler.providers import _determine_scheduler_phase

        phase = _determine_scheduler_phase(
            goal_profile="internal_asset_discovery",
            service="https",
            context={
                "coverage": {
                    "missing": ["missing_cpe_cve_enrichment"],
                }
            },
        )
        self.assertEqual("broad_vuln", phase)

    @patch("app.scheduler.providers.requests.post")
    @patch("app.scheduler.providers.requests.get")
    def test_test_provider_connection_lm_studio(self, mock_get, mock_post):
        from app.scheduler.providers import test_provider_connection

        models_response = MagicMock()
        models_response.status_code = 200
        models_response.json.return_value = {
            "data": [
                {"id": "qwen-7b"},
                {"id": "o3-7b-local"},
            ]
        }
        mock_get.return_value = models_response

        completion_response = MagicMock()
        completion_response.status_code = 200
        completion_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"actions":[{"tool_id":"healthcheck","score":100,'
                            '"rationale":"ok"}]}'
                        )
                    }
                }
            ]
        }
        mock_post.return_value = completion_response

        config = {
            "provider": "lm_studio",
            "providers": {
                "lm_studio": {
                    "enabled": True,
                    "base_url": "http://127.0.0.1:1234/v1",
                    "model": "",
                    "api_key": "",
                }
            },
        }
        result = test_provider_connection(config)
        self.assertTrue(result["ok"])
        self.assertEqual("lm_studio", result["provider"])
        self.assertEqual("o3-7b-local", result["model"])
        self.assertTrue(result["auto_selected_model"])

    @patch("app.scheduler.providers.requests.get")
    def test_lm_studio_model_listing_supports_legacy_models_shape(self, mock_get):
        from app.scheduler.providers import test_provider_connection

        def get_side_effect(url, headers=None, timeout=0):
            response = MagicMock()
            response.status_code = 200
            if url.endswith("/api/v1/models"):
                response.json.return_value = {
                    "models": [
                        {"key": "openai/gpt-oss-20b"},
                        {"key": "openai/gpt-oss-120b"},
                    ]
                }
            elif url.endswith("/v1/models"):
                response.json.return_value = {"data": []}
            else:
                response.json.return_value = {"data": []}
            return response

        mock_get.side_effect = get_side_effect

        with patch("app.scheduler.providers.requests.post") as mock_post:
            completion_response = MagicMock()
            completion_response.status_code = 200
            completion_response.json.return_value = {
                "choices": [
                    {"message": {"content": '{"actions":[{"tool_id":"healthcheck","score":100,"rationale":"ok"}]}'}}
                ]
            }
            mock_post.return_value = completion_response

            config = {
                "provider": "lm_studio",
                "providers": {
                    "lm_studio": {
                        "enabled": True,
                        "base_url": "http://127.0.0.1:1234/v1",
                        "model": "",
                        "api_key": "",
                    }
                },
            }
            result = test_provider_connection(config)
            self.assertTrue(result["ok"])
            self.assertEqual("openai/gpt-oss-20b", result["model"])


if __name__ == "__main__":
    unittest.main()
