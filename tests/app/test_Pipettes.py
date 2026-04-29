import os
import tempfile
import unittest


class PipettesTest(unittest.TestCase):
    def test_loads_bundled_cisco_smart_install_pipette(self):
        from app.pipettes import find_pipette, list_pipettes

        rows = list_pipettes()
        by_id = {item.tool_id: item for item in rows}

        self.assertIn("pipette-cisco-smart-install-check", by_id)
        pipette = find_pipette("pipette-cisco-smart-install-check")
        self.assertIsNotNone(pipette)
        self.assertIn("smart-install", pipette.service_scope)
        self.assertIn("nmap", pipette.required_tools)
        self.assertIn("--target '[IP]'", pipette.command_template)
        self.assertIn("--port '[PORT]'", pipette.command_template)
        self.assertTrue(os.path.isfile(pipette.entrypoint))

    def test_loads_bundled_smtp_internal_discovery_pipette(self):
        from app.pipettes import find_pipette, list_pipettes

        rows = list_pipettes()
        by_id = {item.tool_id: item for item in rows}

        self.assertIn("pipette-smtp-internal-discovery", by_id)
        pipette = find_pipette("pipette-smtp-internal-discovery")
        self.assertIsNotNone(pipette)
        self.assertIn("smtp", pipette.service_scope)
        self.assertIn("25", pipette.target_ports)
        self.assertIn("465", pipette.target_ports)
        self.assertIn("587", pipette.target_ports)
        self.assertIn("2525", pipette.target_ports)
        self.assertIn("nmap", pipette.required_tools)
        self.assertEqual(["spf_domain"], [item["name"] for item in pipette.parameters])
        self.assertIn("--target '[IP]'", pipette.command_template)
        self.assertTrue(os.path.isfile(pipette.entrypoint))

    def test_loads_bundled_windows_systems_discovery_pipette(self):
        from app.pipettes import find_pipette, list_pipettes

        rows = list_pipettes()
        by_id = {item.tool_id: item for item in rows}

        self.assertIn("pipette-windows-systems-discovery", by_id)
        pipette = find_pipette("pipette-windows-systems-discovery")
        self.assertIsNotNone(pipette)
        self.assertIn("microsoft-ds", pipette.service_scope)
        self.assertIn("445", pipette.target_ports)
        self.assertIn("3389", pipette.target_ports)
        self.assertIn("nmap", pipette.required_tools)
        self.assertIn("smbclient", pipette.optional_tools)
        self.assertTrue(os.path.isfile(pipette.entrypoint))

    def test_loads_bundled_ipmi_oob_discovery_pipette(self):
        from app.pipettes import find_pipette, list_pipettes

        rows = list_pipettes()
        by_id = {item.tool_id: item for item in rows}

        self.assertIn("pipette-ipmi-oob-discovery", by_id)
        pipette = find_pipette("pipette-ipmi-oob-discovery")
        self.assertIsNotNone(pipette)
        self.assertIn("ipmi", pipette.service_scope)
        self.assertIn("623", pipette.target_ports)
        self.assertIn("5900", pipette.target_ports)
        self.assertIn("49152", pipette.target_ports)
        self.assertIn("tcp", pipette.protocol_scope)
        self.assertIn("udp", pipette.protocol_scope)
        self.assertIn("nmap", pipette.required_tools)
        self.assertIn("ipmi-cipher-zero", pipette.optional_tools)
        self.assertIn("supermicro-ipmi-conf", pipette.optional_tools)
        self.assertTrue(os.path.isfile(pipette.entrypoint))

    def test_pipette_parameters_render_safe_command_arguments(self):
        from app.pipettes import find_pipette

        pipette = find_pipette("pipette-smtp-internal-discovery")
        self.assertIsNotNone(pipette)

        command = pipette.command_template_for_values({"spf_domain": "example.org"})

        self.assertIn("--domain example.org", command)

    def test_pipette_parameters_reject_invalid_values(self):
        from app.pipettes import find_pipette

        pipette = find_pipette("pipette-smtp-internal-discovery")
        self.assertIsNotNone(pipette)

        with self.assertRaises(ValueError):
            pipette.command_template_for_values({"spf_domain": "example.org;id"})

    def test_ignores_manifest_with_path_traversal_entrypoint(self):
        from app.pipettes import list_pipettes

        for entrypoint in ("../outside.sh", "..\\outside.sh"):
            with self.subTest(entrypoint=entrypoint), tempfile.TemporaryDirectory() as tempdir:
                pipette_dir = os.path.join(tempdir, "bad")
                os.makedirs(pipette_dir)
                with open(os.path.join(pipette_dir, "manifest.json"), "w", encoding="utf-8") as handle:
                    handle.write(
                        '{"id":"bad","label":"Bad","entrypoint":"%s","service_scope":["tcpwrapped"]}'
                        % entrypoint.replace("\\", "\\\\")
                    )

                self.assertNotIn("bad", {item.tool_id for item in list_pipettes(extra_roots=[tempdir])})

    def test_ignores_manifest_entrypoint_that_resolves_outside_source_dir(self):
        from app.pipettes import list_pipettes

        with tempfile.TemporaryDirectory() as tempdir:
            pipette_dir = os.path.join(tempdir, "bad")
            os.makedirs(pipette_dir)
            with open(os.path.join(pipette_dir, "manifest.json"), "w", encoding="utf-8") as handle:
                handle.write(
                    '{"id":"bad","label":"Bad","entrypoint":"nested/../../outside.sh","service_scope":["tcpwrapped"]}'
                )

            self.assertNotIn("bad", {item.tool_id for item in list_pipettes(extra_roots=[tempdir])})


if __name__ == "__main__":
    unittest.main()
