import unittest


class _RouteRuntime:
    def __init__(self):
        self.calls = []

    def get_project_details(self):
        self.calls.append(("get_project_details",))
        return {"name": "demo.legion"}

    def list_projects(self, limit=500):
        self.calls.append(("list_projects", int(limit)))
        return [{"name": "demo.legion"}]

    def create_new_temporary_project(self):
        self.calls.append(("create_new_temporary_project",))
        return {"name": "temp.legion"}

    def open_project(self, path):
        self.calls.append(("open_project", str(path)))
        return {"name": str(path)}

    def start_save_project_as_job(self, path, replace=True):
        self.calls.append(("start_save_project_as_job", str(path), bool(replace)))
        return {"id": 41}

    def start_targets_import_job(self, path):
        self.calls.append(("start_targets_import_job", str(path)))
        return {"id": 51}

    def start_nmap_xml_import_job(self, path, run_actions=False):
        self.calls.append(("start_nmap_xml_import_job", str(path), bool(run_actions)))
        return {"id": 61}

    def start_nmap_scan_job(self, **kwargs):
        self.calls.append(("start_nmap_scan_job", dict(kwargs)))
        return {"id": 71}

    def get_capture_interface_inventory(self):
        self.calls.append(("get_capture_interface_inventory",))
        return {"interfaces": [{"name": "eth0"}], "default_interface": "eth0"}

    def start_passive_capture_scan_job(self, *, interface_name, duration_minutes, run_actions=False):
        self.calls.append(("start_passive_capture_scan_job", str(interface_name), int(duration_minutes), bool(run_actions)))
        return {"id": 81}

    def start_host_rescan_job(self, host_id):
        self.calls.append(("start_host_rescan_job", int(host_id)))
        return {"id": 91}

    def start_subnet_rescan_job(self, subnet):
        self.calls.append(("start_subnet_rescan_job", str(subnet)))
        return {"id": 101}

    def get_scan_history(self, limit=100):
        self.calls.append(("get_scan_history", int(limit)))
        return [{"submission_kind": "nmap_scan", "target_summary": "10.0.0.0/24"}]


class WebProjectAndScanRoutesTest(unittest.TestCase):
    def setUp(self):
        from app.web import create_app

        self.runtime = _RouteRuntime()
        self.client = create_app(self.runtime).test_client()

    def test_project_routes_delegate_to_project_service(self):
        details = self.client.get("/api/project")
        self.assertEqual(200, details.status_code)
        self.assertEqual("demo.legion", details.json["name"])

        listing = self.client.get("/api/projects?limit=25")
        self.assertEqual(200, listing.status_code)
        self.assertEqual("demo.legion", listing.json["projects"][0]["name"])

        new_temp = self.client.post("/api/project/new-temp", json={})
        self.assertEqual(200, new_temp.status_code)
        self.assertEqual("ok", new_temp.json["status"])

        opened = self.client.post("/api/project/open", json={"path": "/tmp/example.legion"})
        self.assertEqual(200, opened.status_code)
        self.assertEqual("/tmp/example.legion", opened.json["project"]["name"])

        saved = self.client.post("/api/project/save-as", json={"path": "/tmp/saved.legion", "replace": False})
        self.assertEqual(202, saved.status_code)
        self.assertEqual("accepted", saved.json["status"])

    def test_scan_routes_delegate_to_scan_service(self):
        imported_targets = self.client.post("/api/targets/import-file", json={"path": "/tmp/targets.txt"})
        self.assertEqual(202, imported_targets.status_code)
        self.assertEqual(51, imported_targets.json["job"]["id"])

        imported_xml = self.client.post("/api/nmap/import-xml", json={"path": "/tmp/scan.xml", "run_actions": True})
        self.assertEqual(202, imported_xml.status_code)
        self.assertEqual(61, imported_xml.json["job"]["id"])

        scan = self.client.post("/api/nmap/scan", json={"targets": ["10.0.0.5"], "run_actions": True})
        self.assertEqual(202, scan.status_code)
        self.assertEqual(71, scan.json["job"]["id"])

        interfaces = self.client.get("/api/network/interfaces")
        self.assertEqual(200, interfaces.status_code)
        self.assertEqual("eth0", interfaces.json["default_interface"])

        passive = self.client.post("/api/scan/passive-capture", json={"interface_name": "eth0", "duration_minutes": 15})
        self.assertEqual(202, passive.status_code)
        self.assertEqual(81, passive.json["job"]["id"])

        host_rescan = self.client.post("/api/workspace/hosts/11/rescan", json={})
        self.assertEqual(202, host_rescan.status_code)
        self.assertEqual(91, host_rescan.json["job"]["id"])

        subnet_rescan = self.client.post("/api/workspace/subnets/rescan", json={"subnet": "10.0.0.0/24"})
        self.assertEqual(202, subnet_rescan.status_code)
        self.assertEqual(101, subnet_rescan.json["job"]["id"])

        history = self.client.get("/api/scans/history?limit=25")
        self.assertEqual(200, history.status_code)
        self.assertEqual("nmap_scan", history.json["scans"][0]["submission_kind"])


if __name__ == "__main__":
    unittest.main()
