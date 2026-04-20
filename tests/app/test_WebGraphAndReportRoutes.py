import tempfile
import unittest
import zipfile


class _GraphReportRuntime:
    def __init__(self):
        self.calls = []

    def get_evidence_graph(self, filters=None):
        self.calls.append(("get_evidence_graph", dict(filters or {})))
        return {"nodes": [], "edges": [], "meta": {"filters": dict(filters or {})}}

    def rebuild_evidence_graph(self, host_id=None):
        self.calls.append(("rebuild_evidence_graph", host_id))
        return {"host_id": host_id}

    def export_evidence_graph_json(self, rebuild=False):
        self.calls.append(("export_evidence_graph_json", bool(rebuild)))
        return {"nodes": [{"id": "host-1"}]}

    def export_evidence_graph_graphml(self, rebuild=False):
        self.calls.append(("export_evidence_graph_graphml", bool(rebuild)))
        return "<graphml />"

    def get_graph_related_content(self, node_id, max_chars=12000):
        self.calls.append(("get_graph_related_content", str(node_id), int(max_chars)))
        return {"items": [{"node_id": str(node_id)}]}

    def get_graph_content(self, node_id, *, download=False, max_chars=12000):
        self.calls.append(("get_graph_content", str(node_id), bool(download), int(max_chars)))
        return {
            "text": f"content for {node_id}",
            "mimetype": "text/plain; charset=utf-8",
            "download": bool(download),
            "filename": f"{node_id}.txt",
        }

    def get_evidence_graph_layouts(self):
        self.calls.append(("get_evidence_graph_layouts",))
        return [{"layout_id": "layout-1"}]

    def save_evidence_graph_layout(self, *, view_id, name, layout_state, layout_id=""):
        self.calls.append(("save_evidence_graph_layout", str(view_id), str(name), dict(layout_state), str(layout_id)))
        return {"layout_id": layout_id or "layout-1", "view_id": view_id, "name": name}

    def get_evidence_graph_annotations(self, *, target_ref="", target_kind=""):
        self.calls.append(("get_evidence_graph_annotations", str(target_ref), str(target_kind)))
        return [{"annotation_id": "annotation-1", "target_ref": target_ref, "target_kind": target_kind}]

    def save_evidence_graph_annotation(
        self,
        *,
        target_kind,
        target_ref,
        body,
        created_by="operator",
        source_ref="",
        annotation_id="",
    ):
        self.calls.append(
            (
                "save_evidence_graph_annotation",
                str(target_kind),
                str(target_ref),
                str(body),
                str(created_by),
                str(source_ref),
                str(annotation_id),
            )
        )
        return {"annotation_id": annotation_id or "annotation-1", "body": body, "target_ref": target_ref}

    def get_host_ai_report(self, host_id):
        self.calls.append(("get_host_ai_report", int(host_id)))
        return {"host": {"id": int(host_id), "ip": "10.0.0.5"}, "ai_analysis": {"provider": "demo"}}

    def render_host_ai_report_markdown(self, report):
        self.calls.append(("render_host_ai_report_markdown", dict(report or {})))
        return "# Legion Host AI Report\n"

    def get_host_report(self, host_id):
        self.calls.append(("get_host_report", int(host_id)))
        return {"host": {"id": int(host_id), "ip": "10.0.0.5"}, "validated_findings": {"count": 1}}

    def render_host_report_markdown(self, report):
        self.calls.append(("render_host_report_markdown", dict(report or {})))
        return "# Legion Host Report\n"

    def build_host_ai_reports_zip(self):
        self.calls.append(("build_host_ai_reports_zip",))
        handle = tempfile.NamedTemporaryFile(prefix="legion-report-bundle-", suffix=".zip", delete=False)
        handle.close()
        with zipfile.ZipFile(handle.name, "w") as archive:
            archive.writestr("reports/host-1.md", "# Legion Host AI Report\n")
        return handle.name, "legion-ai-reports.zip"

    def get_project_ai_report(self):
        self.calls.append(("get_project_ai_report",))
        return {"project": {"name": "demo.legion"}, "host_count": 1}

    def render_project_ai_report_markdown(self, report):
        self.calls.append(("render_project_ai_report_markdown", dict(report or {})))
        return "# Legion Project AI Report\n"

    def get_project_report(self):
        self.calls.append(("get_project_report",))
        return {"project": {"name": "demo.legion"}, "summary_of_discovered_assets": {"host_count": 1}}

    def render_project_report_markdown(self, report):
        self.calls.append(("render_project_report_markdown", dict(report or {})))
        return "# Legion Project Report\n"

    def push_project_ai_report(self, overrides=None):
        self.calls.append(("push_project_ai_report", dict(overrides or {})))
        return {"ok": True, "endpoint": "https://example.local/ai"}

    def push_project_report(self, overrides=None):
        self.calls.append(("push_project_report", dict(overrides or {})))
        return {"ok": True, "endpoint": "https://example.local/report"}


class WebGraphAndReportRoutesTest(unittest.TestCase):
    def setUp(self):
        from app.web import create_app

        self.runtime = _GraphReportRuntime()
        self.client = create_app(self.runtime).test_client()

    def test_graph_routes_delegate_to_graph_service(self):
        graph = self.client.get("/api/graph?node_types=host&host_id=11&include_ai_suggested=false&limit_nodes=10")
        self.assertEqual(200, graph.status_code)
        self.assertEqual(["host"], graph.json["meta"]["filters"]["node_types"])
        self.assertEqual(11, graph.json["meta"]["filters"]["host_id"])
        self.assertFalse(graph.json["meta"]["filters"]["include_ai_suggested"])

        rebuild = self.client.post("/api/graph/rebuild", json={"host_id": 11})
        self.assertEqual(200, rebuild.status_code)
        self.assertEqual("ok", rebuild.json["status"])

        export_json = self.client.get("/api/graph/export/json?rebuild=true")
        self.assertEqual(200, export_json.status_code)
        self.assertIn("application/json", str(export_json.content_type))
        self.assertIn("attachment; filename=", export_json.headers.get("Content-Disposition", ""))

        export_graphml = self.client.get("/api/graph/export/graphml")
        self.assertEqual(200, export_graphml.status_code)
        self.assertIn("application/graphml+xml", str(export_graphml.content_type))

        node_content = self.client.get("/api/graph/nodes/host-1/content?max_chars=42")
        self.assertEqual(200, node_content.status_code)
        self.assertEqual("host-1", node_content.json["items"][0]["node_id"])

        content = self.client.get("/api/graph/content/host-1?download=true")
        self.assertEqual(200, content.status_code)
        self.assertIn("attachment; filename=", content.headers.get("Content-Disposition", ""))

        layouts = self.client.get("/api/graph/layouts")
        self.assertEqual(200, layouts.status_code)
        self.assertEqual("layout-1", layouts.json["layouts"][0]["layout_id"])

        saved_layout = self.client.post(
            "/api/graph/layouts",
            json={"view_id": "default", "name": "ops", "layout": {"x": 10}, "layout_id": "layout-2"},
        )
        self.assertEqual(200, saved_layout.status_code)
        self.assertEqual("layout-2", saved_layout.json["layout"]["layout_id"])

        annotations = self.client.get("/api/graph/annotations?target_ref=host-1&target_kind=node")
        self.assertEqual(200, annotations.status_code)
        self.assertEqual("host-1", annotations.json["annotations"][0]["target_ref"])

        saved_annotation = self.client.post(
            "/api/graph/annotations",
            json={"target_kind": "node", "target_ref": "host-1", "body": "focus this node"},
        )
        self.assertEqual(200, saved_annotation.status_code)
        self.assertEqual("focus this node", saved_annotation.json["annotation"]["body"])

    def test_report_routes_delegate_to_report_service(self):
        host_ai_json = self.client.get("/api/workspace/hosts/11/ai-report?format=json")
        self.assertEqual(200, host_ai_json.status_code)
        self.assertIn("application/json", str(host_ai_json.content_type))
        self.assertIn("attachment; filename=", host_ai_json.headers.get("Content-Disposition", ""))

        host_report_md = self.client.get("/api/workspace/hosts/11/report?format=md")
        self.assertEqual(200, host_report_md.status_code)
        self.assertIn("text/markdown", str(host_report_md.content_type))
        self.assertIn("# Legion Host Report", host_report_md.get_data(as_text=True))

        project_ai_report = self.client.get("/api/workspace/project-ai-report?format=md")
        self.assertEqual(200, project_ai_report.status_code)
        self.assertIn("# Legion Project AI Report", project_ai_report.get_data(as_text=True))

        project_report = self.client.get("/api/workspace/project-report?format=json")
        self.assertEqual(200, project_report.status_code)
        self.assertIn("summary_of_discovered_assets", project_report.get_data(as_text=True))

        push_ai = self.client.post(
            "/api/workspace/project-ai-report/push",
            json={"project_report_delivery": {"endpoint": "https://example.local/ai", "method": "POST"}},
        )
        self.assertEqual(200, push_ai.status_code)
        self.assertEqual("ok", push_ai.json["status"])

        push_report = self.client.post(
            "/api/workspace/project-report/push",
            json={"project_report_delivery": {"endpoint": "https://example.local/report", "method": "POST"}},
        )
        self.assertEqual(200, push_report.status_code)
        self.assertEqual("ok", push_report.json["status"])

        bundle = self.client.get("/api/workspace/ai-reports/download-zip")
        self.assertEqual(200, bundle.status_code)
        self.assertIn("application/zip", str(bundle.content_type))
        bundle.get_data()
        bundle.close()
        self.assertIn(("build_host_ai_reports_zip",), self.runtime.calls)


if __name__ == "__main__":
    unittest.main()
