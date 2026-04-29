import unittest
from types import SimpleNamespace

from app.device_categories import category_names, classify_device_categories


class DeviceCategoriesTest(unittest.TestCase):
    def test_phone_signaling_classifies_phone_and_suppresses_generic_server(self):
        rows = classify_device_categories({
            "hostname": "lobby-phone.local",
            "service_inventory": [
                {"port": "80", "protocol": "tcp", "state": "open", "service": "http"},
                {"port": "443", "protocol": "tcp", "state": "open", "service": "https"},
                {
                    "port": "5060",
                    "protocol": "udp",
                    "state": "open",
                    "service": "sip",
                    "service_product": "Grandstream SIP phone",
                },
            ],
        })

        names = category_names(rows)
        self.assertIn("Phone", names)
        self.assertNotIn("Server", names)

    def test_rtp_service_evidence_classifies_phone_without_broad_port_ranges(self):
        rows = classify_device_categories({
            "service_inventory": [
                {
                    "port": "16384",
                    "protocol": "udp",
                    "state": "open",
                    "service": "rtp",
                    "service_product": "SRTP media endpoint",
                },
            ],
        })

        self.assertIn("Phone", category_names(rows))

    def test_workspace_resolution_refreshes_stale_auto_categories(self):
        from app.web.runtime_workspace_read import resolve_host_device_categories

        runtime = SimpleNamespace(
            scheduler_config=SimpleNamespace(get_device_categories=lambda: []),
        )
        result = resolve_host_device_categories(
            runtime,
            SimpleNamespace(database=None),
            SimpleNamespace(id=1, hostname="lobby-phone", osMatch=""),
            target_state={
                "device_categories": [{"name": "Server", "origin": "auto"}],
                "device_category_override": False,
                "service_inventory": [
                    {
                        "port": "5060",
                        "protocol": "tcp",
                        "state": "open",
                        "service": "sip",
                        "service_product": "Grandstream SIP phone",
                    },
                ],
            },
        )

        names = category_names(result.get("device_categories", []))
        self.assertIn("Phone", names)
        self.assertNotIn("Server", names)

    def test_workspace_os_resolution_overrides_weak_imported_os_with_strong_service_evidence(self):
        from app.web.runtime_workspace_read import resolve_host_os

        result = resolve_host_os(
            SimpleNamespace(id=1, hostname="patrol-04", osMatch="iOS", osAccuracy="NaN"),
            service_inventory=[
                {
                    "port": "135",
                    "protocol": "tcp",
                    "state": "open",
                    "service": "msrpc",
                    "service_product": "Microsoft Windows RPC",
                },
                {
                    "port": "139",
                    "protocol": "tcp",
                    "state": "open",
                    "service": "netbios-ssn",
                    "service_product": "Microsoft Windows netbios-ssn",
                },
                {
                    "port": "445",
                    "protocol": "tcp",
                    "state": "open",
                    "service": "microsoft-ds",
                },
                {
                    "port": "3389",
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ms-wbt-server",
                },
            ],
        )

        self.assertEqual("Windows", result.get("os"))
        self.assertEqual("iOS", result.get("raw_os"))
        self.assertEqual("service-evidence", result.get("os_source"))

    def test_workspace_os_resolution_keeps_high_confidence_imported_os(self):
        from app.web.runtime_workspace_read import resolve_host_os

        result = resolve_host_os(
            SimpleNamespace(id=1, hostname="mobile", osMatch="iOS", osAccuracy="98"),
            service_inventory=[
                {
                    "port": "22",
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "service_product": "OpenSSH",
                },
            ],
        )

        self.assertEqual("iOS", result.get("os"))
        self.assertEqual("imported", result.get("os_source"))


if __name__ == "__main__":
    unittest.main()
