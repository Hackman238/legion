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
        payload = mock_post.call_args.kwargs["json"]
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
        self.assertLessEqual(len(prompt), 3400)
        self.assertIn("omitted due to context budget", prompt)

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
                },
            },
        )
        payload = mock_post.call_args.kwargs["json"]
        prompt = payload["messages"][1]["content"]
        self.assertIn("Context:", prompt)
        self.assertIn("Current phase:", prompt)
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
        self.assertIn("coverage", prompt)
        self.assertIn("missing_nmap_vuln", prompt)
        self.assertIn("host_cves", prompt)
        self.assertIn("inferred_technologies", prompt)
        self.assertIn("jetty", prompt.lower())

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
