"""
Shared Nmap XML import entrypoint used by web, headless CLI, and MCP modes.
"""

import os

from app.importers.NmapImporter import NmapImporter
from app.importers.scan_converters import convert_report_to_nmap_xml


def import_nmap_xml_into_project(
        project,
        xml_path: str,
        output: str = "",
        update_progress_observable=None,
        host_repository=None,
):
    """Import a scan report. Nmap XML is read directly; .gnmap and masscan XML/JSON/list output are converted to
    nmap XML (next to the project's running folder) first, so every caller accepts every supported format."""
    repo = host_repository or project.repositoryContainer.hostRepository
    running_folder = str(getattr(getattr(project, "properties", None), "runningFolder", "") or "")
    xml_path, _detected = convert_report_to_nmap_xml(
        xml_path,
        output_dir=running_folder if running_folder and os.path.isdir(running_folder) else None,
    )
    importer = NmapImporter(update_progress_observable, repo)
    importer.setDB(project.database)
    importer.setHostRepository(repo)
    importer.setFilename(xml_path)
    importer.setOutput(str(output or ""))
    importer.importFile()
    return importer
