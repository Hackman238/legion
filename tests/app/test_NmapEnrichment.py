import unittest

from app.nmap_enrichment import (
    infer_hostname_from_nmap_data,
    infer_os_from_service_inventory,
    infer_os_from_nmap_scripts,
    is_unknown_hostname,
)


class NmapEnrichmentTest(unittest.TestCase):
    def test_infer_hostname_from_ssl_cert_script(self):
        scripts = [
            (
                "ssl-cert",
                "Subject: commonName=unifi.local\n"
                "Subject Alternative Name: DNS:unifi.local, DNS:localhost\n",
            )
        ]
        inferred = infer_hostname_from_nmap_data("unknown", scripts)
        self.assertEqual("unifi.local", inferred)

    def test_prefers_primary_hostname_when_valid(self):
        scripts = [("ssl-cert", "Subject: commonName=printer.local")]
        inferred = infer_hostname_from_nmap_data("gateway.local", scripts)
        self.assertEqual("gateway.local", inferred)

    def test_infer_os_from_script_output(self):
        scripts = [
            ("smb-os-discovery.nse", "OS: Microsoft Windows Server 2019 Standard"),
        ]
        inferred = infer_os_from_nmap_scripts(scripts)
        self.assertEqual("Windows", inferred)

    def test_infer_os_from_service_inventory(self):
        services = [
            ("msrpc", "Microsoft Windows RPC", "", ""),
            ("vmrdp", "", "", ""),
            ("x11", "VcXsrv X server", "", ""),
        ]
        inferred = infer_os_from_service_inventory(services)
        self.assertEqual("Windows", inferred)

    def test_unknown_hostname_helper(self):
        self.assertTrue(is_unknown_hostname("unknown"))
        self.assertTrue(is_unknown_hostname(""))
        self.assertFalse(is_unknown_hostname("host.local"))


if __name__ == "__main__":
    unittest.main()
