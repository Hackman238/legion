import unittest
from types import SimpleNamespace

from app.ProjectManager import ProjectManager
from app.logging.legionLog import getAppLogger, getDbLogger
from app.shell.DefaultShell import DefaultShell
from app.web import configure_web_token, create_app
from app.web.runtime import WebRuntime
from app.logic import Logic
from app.tools.ToolCoordinator import ToolCoordinator
from app.tools.nmap.DefaultNmapExporter import DefaultNmapExporter
from db.RepositoryFactory import RepositoryFactory


class WebTokenAuthTest(unittest.TestCase):
    def setUp(self):
        shell = DefaultShell()
        project_manager = ProjectManager(shell, RepositoryFactory(getDbLogger()), getAppLogger())
        logic = Logic(shell, project_manager, ToolCoordinator(shell, DefaultNmapExporter(shell, getAppLogger())))
        logic.createNewTemporaryProject()
        runtime = WebRuntime(logic)
        self.addCleanup(lambda: project_manager.closeProject(logic.activeProject))
        self.app = create_app(runtime)
        self.app.config["TESTING"] = True
        configure_web_token(self.app, "s3cret-token")
        self.client = self.app.test_client()

    def test_api_requires_the_token(self):
        self.assertEqual(401, self.client.get("/api/snapshot").status_code)
        self.assertEqual(200, self.client.get("/api/snapshot", headers={"Authorization": "Bearer s3cret-token"}).status_code)
        self.assertEqual(200, self.client.get("/api/snapshot", headers={"X-Legion-Token": "s3cret-token"}).status_code)
        self.assertEqual(401, self.client.get("/api/snapshot", headers={"Authorization": "Bearer wrong"}).status_code)
        self.assertEqual(200, self.client.get("/health").status_code)  # health stays open for probes
        # A browser following an API link (export downloads) sends a real navigation Accept header, */* included,
        # and must land on the login page; a JSON client keeps getting 401.
        browser_accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        navigated = self.client.get("/api/export/table/hosts.csv", headers={"Accept": browser_accept})
        self.assertEqual(302, navigated.status_code)
        self.assertTrue(navigated.headers["Location"].endswith("/login"))
        self.assertEqual(401, self.client.get("/api/export/table/hosts.csv", headers={"Accept": "application/json, text/plain, */*"}).status_code)

    def test_page_redirects_to_login_and_cookie_grants_access(self):
        response = self.client.get("/")
        self.assertEqual(302, response.status_code)
        self.assertTrue(response.headers["Location"].endswith("/login"))
        self.assertEqual(200, self.client.get("/login").status_code)
        self.assertEqual(401, self.client.post("/login", data={"token": "nope"}).status_code)
        login = self.client.post("/login", data={"token": "s3cret-token"})
        self.assertEqual(302, login.status_code)
        self.assertIn("legion_token=", login.headers.get("Set-Cookie", ""))
        self.assertIn("HttpOnly", login.headers.get("Set-Cookie", ""))
        page = self.client.get("/")
        self.assertEqual(200, page.status_code)
        self.assertIn(b"Token auth", page.data)
        self.assertEqual(200, self.client.get("/api/snapshot").status_code)  # cookie carries the API too
        self.assertEqual(302, self.client.post("/logout").status_code)
        self.assertEqual(401, self.client.get("/api/snapshot").status_code)

    def test_non_ascii_token_is_compared_not_crashed(self):
        from app.web import configure_web_token

        configure_web_token(self.app, "Passw\u00f6rd-2026")
        self.assertEqual(401, self.client.get("/api/snapshot", headers={"Authorization": "Bearer wrong"}).status_code)
        # A real client puts the UTF-8 bytes on the wire; WSGI hands them to Flask decoded as latin-1.
        on_the_wire = "Passw\u00f6rd-2026".encode("utf-8").decode("latin-1")
        self.assertEqual(200, self.client.get("/api/snapshot", headers={"X-Legion-Token": on_the_wire}).status_code)
        self.assertEqual(200, self.client.get("/api/snapshot", headers={"X-Legion-Token": "Passw\u00f6rd-2026"}).status_code)
        self.assertEqual(302, self.client.post("/login", data={"token": "Passw\u00f6rd-2026"}).status_code)

    def test_without_a_token_nothing_changes(self):
        other = create_app(WebRuntime(self.app.extensions["legion_runtime"].logic))
        other.config["TESTING"] = True
        client = other.test_client()
        self.assertEqual(200, client.get("/api/snapshot").status_code)
        self.assertEqual(302, client.get("/login").status_code)  # no token configured: login just redirects home

    def test_token_resolution_generates_one_when_exposed(self):
        import legion
        args = SimpleNamespace(web_token="", web_bind_all=False)
        self.assertEqual("", legion.resolve_web_token(args, environ={}))
        self.assertEqual("from-env", legion.resolve_web_token(args, environ={"LEGION_WEB_TOKEN": "from-env"}))
        exposed = SimpleNamespace(web_token="", web_bind_all=True)
        self.assertEqual("generated", legion.resolve_web_token(exposed, environ={}, generate=lambda: "generated"))
        explicit = SimpleNamespace(web_token="given", web_bind_all=True)
        self.assertEqual("given", legion.resolve_web_token(explicit, environ={"LEGION_WEB_TOKEN": "env"}))


if __name__ == "__main__":
    unittest.main()
