from app.ProjectManager import ProjectManager
from app.logic import Logic
from app.logging.legionLog import getAppLogger, getDbLogger
from app.shell.DefaultShell import DefaultShell
from app.tools.ToolCoordinator import ToolCoordinator
from app.tools.nmap.DefaultNmapExporter import DefaultNmapExporter
from db.RepositoryFactory import RepositoryFactory


def create_default_logic():
    shell = DefaultShell()
    db_log = getDbLogger()
    app_log = getAppLogger()
    repository_factory = RepositoryFactory(db_log)
    project_manager = ProjectManager(shell, repository_factory, app_log)
    nmap_exporter = DefaultNmapExporter(shell, app_log)
    tool_coordinator = ToolCoordinator(shell, nmap_exporter)
    logic = Logic(shell, project_manager, tool_coordinator)
    logic.createNewTemporaryProject()
    return logic
