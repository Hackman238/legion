import unittest
from unittest.mock import MagicMock

from sqlalchemy import event, text

from db.entities.host import hostObj
from db.entities.l1script import l1ScriptObj
from db.entities.port import portObj


def _insert_process(session, *, name, host_ip, port, protocol="tcp", status="Finished", output=None):
    inserted = session.execute(text(
        "INSERT INTO process (name, hostIp, port, protocol, command, status) "
        "VALUES (:name, :host_ip, :port, :protocol, 'echo test', :status)"
    ), {"name": name, "host_ip": host_ip, "port": port, "protocol": protocol, "status": status})
    process_id = int(inserted.lastrowid or 0)
    if output is not None:
        session.execute(text(
            "INSERT INTO process_output (processId, output) VALUES (:process_id, :output)"
        ), {"process_id": process_id, "output": output})
    return process_id


class WebRuntimeOutputLoadingTest(unittest.TestCase):
    """Stored tool output is read in slices/once per request instead of whole on every call."""

    def setUp(self):
        from app.ProjectManager import ProjectManager
        from app.logic import Logic
        from app.logging.legionLog import getAppLogger, getDbLogger
        from app.shell.DefaultShell import DefaultShell
        from app.web.runtime import WebRuntime
        from db.RepositoryFactory import RepositoryFactory

        shell = DefaultShell()
        self.project_manager = ProjectManager(shell, RepositoryFactory(getDbLogger()), getAppLogger())
        self.logic = Logic(shell, self.project_manager, MagicMock())
        self.runtime = WebRuntime(self.logic)
        self.project = self.project_manager.createNewProject(projectType="legion", isTemp=True)
        self.logic.activeProject = self.project
        self.runtime._ensure_process_tables()
        session = self.project.database.session()
        try:
            host = hostObj(ip="10.0.0.5", hostname="web01", status="up")
            session.add(host)
            session.flush()
            self.host_id = int(host.id)
            port = portObj("80", "tcp", "open", str(host.id), "")
            session.add(port)
            session.flush()
            self.port_db_id = int(port.id)
            session.commit()
        finally:
            session.close()

    def tearDown(self):
        if getattr(self.logic, "activeProject", None) is not None:
            self.runtime._close_active_project()

    def _count_process_output_reads(self):
        statements = []

        def _listener(_conn, _cursor, statement, _parameters, _context, _executemany):
            if "process_output" in statement and statement.lstrip().upper().startswith("SELECT"):
                statements.append(statement)

        engine = self.project.database.engine
        event.listen(engine, "before_cursor_execute", _listener)
        self.addCleanup(event.remove, engine, "before_cursor_execute", _listener)
        return statements

    def test_host_workspace_reads_each_process_output_once_and_only_its_head(self):
        from app.web import runtime_scheduler_host_inference

        huge_output = "Server: nginx/1.25.3\n" + ("filler line\n" * 40000) + "\nTAIL-MARKER http://10.0.0.5/never-read"
        self.assertGreater(len(huge_output), runtime_scheduler_host_inference.PROCESS_OUTPUT_HEAD_CHARS)
        nul_output = "before-nul\x00http://10.0.0.5/after-nul"
        session = self.project.database.session()
        try:
            _insert_process(session, name="whatweb", host_ip="10.0.0.5", port="80", output=huge_output)
            _insert_process(session, name="nikto", host_ip="10.0.0.5", port="80", output=nul_output)
            _insert_process(session, name="dirb", host_ip="10.0.0.5", port="80", output="+ http://10.0.0.5/admin (CODE:200)")
            session.commit()
        finally:
            session.close()

        excerpt_inputs = []
        build_excerpt = type(self.runtime)._build_scheduler_analysis_excerpt

        def _spy(value, max_chars):
            excerpt_inputs.append(str(value or ""))
            return build_excerpt(value, max_chars)

        self.runtime._build_scheduler_analysis_excerpt = _spy
        reads = self._count_process_output_reads()

        payload = self.runtime.get_host_workspace(self.host_id)

        # Technologies, findings and URLs are all inferred for the host, from one read of its process outputs.
        self.assertEqual(1, len(reads), reads)
        urls = {str(item.get("url", "")) for item in payload["target_state"].get("urls", [])}
        self.assertIn("http://10.0.0.5/admin", urls)
        self.assertIn("http://10.0.0.5/after-nul", urls)  # output holding a NUL byte is still read whole
        huge_inputs = [value for value in excerpt_inputs if value.startswith("Server: nginx")]
        self.assertEqual(1, len(huge_inputs))
        self.assertEqual(runtime_scheduler_host_inference.PROCESS_OUTPUT_HEAD_CHARS, len(huge_inputs[0]))
        self.assertNotIn("TAIL-MARKER", huge_inputs[0])
        nul_inputs = [value for value in excerpt_inputs if value.startswith("before-nul")]
        self.assertEqual([nul_output], nul_inputs)
        self.assertTrue(any(item.get("name", "").lower() == "nginx" for item in payload["ai_analysis"]["technologies"]))

    def test_get_script_output_slices_in_sql_without_shipping_the_whole_output(self):
        script_output = "script-" + ("y" * 3000) + "-end"
        process_output = "proc\x00" + ("z" * 2000) + "-end"
        session = self.project.database.session()
        try:
            plain_script = l1ScriptObj("http-title", script_output, str(self.port_db_id), str(self.host_id))
            process_script = l1ScriptObj("nikto", "row output", str(self.port_db_id), str(self.host_id))
            session.add_all([plain_script, process_script])
            session.flush()
            plain_id, process_script_id = int(plain_script.id), int(process_script.id)
            process_id = _insert_process(
                session, name="nikto", host_ip="10.0.0.5", port="80", status="Running", output=process_output,
            )
            session.commit()
        finally:
            session.close()

        reads = self._count_process_output_reads()
        payload = self.runtime.get_script_output(plain_id, offset=7, max_chars=300)
        self.assertNotIn("output", payload)
        self.assertEqual("script-row", payload["source"])
        self.assertEqual(script_output[7:307], payload["output_chunk"])
        self.assertEqual(len(script_output), payload["output_length"])
        self.assertEqual(307, payload["next_offset"])
        self.assertTrue(payload["completed"])
        self.assertEqual("Saved", payload["status"])
        for statement in reads:
            self.assertNotIn("COALESCE(o.output, '') AS output", statement)  # never the whole blob

        # A process output holding a NUL byte still comes back complete (SQLite text functions stop at NUL).
        process_payload = self.runtime.get_script_output(process_script_id, offset=3, max_chars=5000)
        self.assertEqual("process", process_payload["source"])
        self.assertEqual(process_id, process_payload["process_id"])
        self.assertEqual(process_output[3:], process_payload["output_chunk"])
        self.assertEqual(len(process_output), process_payload["output_length"])
        self.assertFalse(process_payload["completed"])
        self.assertNotIn("output", process_payload)

        past_end = self.runtime.get_script_output(plain_id, offset=len(script_output) + 5)
        self.assertEqual("", past_end["output_chunk"])
        self.assertEqual(len(script_output), past_end["output_length"])

    def test_get_process_output_tail_keeps_the_tail_after_an_embedded_nul(self):
        nul_output = "head\x00middle-tail"
        session = self.project.database.session()
        try:
            nul_id = _insert_process(session, name="tool", host_ip="10.0.0.5", port="80", output=nul_output)
            plain_id = _insert_process(session, name="tool", host_ip="10.0.0.5", port="80", output="plain-tail")
            session.commit()
        finally:
            session.close()

        self.assertEqual(nul_output[-6:], self.runtime.get_process_output_tail(nul_id, max_chars=6))
        self.assertEqual(nul_output, self.runtime.get_process_output_tail(nul_id, max_chars=4000))
        self.assertEqual("-tail", self.runtime.get_process_output_tail(plain_id, max_chars=5))


if __name__ == "__main__":
    unittest.main()
