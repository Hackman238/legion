import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncio
import json
import sys
from typing import Any, Dict, Callable

class MCPServer:
    def __init__(self):
        self.tools = {
            "list_projects": {
                "description": "List all Legion projects",
                "inputSchema": {"type": "object", "properties": {}, "required": []},
                "handler": self.list_projects,
            },
            "run_discovery": {
                "description": "Run a quick discovery scan (nmap -F) on a target (default: localhost)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target host or IP (default: localhost)"}
                    },
                    "required": []
                },
                "handler": self.run_discovery,
            },
            # Add more tools here as needed
        }

    async def list_projects(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        # List all .legion files in the Legion temp folder
        import os
        from app.auxiliary import getTempFolder

        temp_folder = getTempFolder()
        projects = []
        for fname in os.listdir(temp_folder):
            if fname.endswith(".legion"):
                projects.append(fname)
        return {"projects": projects}

    async def run_discovery(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import sys
        debug_info = {
            "sys_executable": sys.executable,
            "sys_path": sys.path,
        }
        try:
            import tempfile
            import time
            import os

            from app.shell.DefaultShell import DefaultShell
            from app.logging.legionLog import getDbLogger, getAppLogger
            from db.RepositoryFactory import RepositoryFactory
            from app.ProjectManager import ProjectManager
            from app.tools.nmap.DefaultNmapExporter import DefaultNmapExporter
            from app.tools.ToolCoordinator import ToolCoordinator
            from app.logic import Logic
            from app.cli_utils import run_nmap_scan
            from app.importers.NmapImporter import NmapImporter

            target = arguments.get("target", "localhost")
            # Setup Legion core components
            shell = DefaultShell()
            dbLog = getDbLogger()
            appLogger = getAppLogger()
            repositoryFactory = RepositoryFactory(dbLog)
            projectManager = ProjectManager(shell, repositoryFactory, appLogger)
            nmapExporter = DefaultNmapExporter(shell, appLogger)
            toolCoordinator = ToolCoordinator(shell, nmapExporter)
            logic = Logic(shell, projectManager, toolCoordinator)
            logic.createNewTemporaryProject()

            # Add target to project (simulate import_targets_from_textfile for a single host)
            session = logic.activeProject.database.session()
            hostRepository = logic.activeProject.repositoryContainer.hostRepository
            # Only add if not already present
            db_host = hostRepository.getHostInformation(target)
            if not db_host:
                from db.entities.host import hostObj
                hid = hostObj(ip=target, ipv4=target, ipv6='', macaddr='', status='', hostname=target,
                              vendor='', uptime='', lastboot='', distance='', state='', count='')
                session.add(hid)
                session.commit()

            # Run nmap scan using Legion's logic
            output_prefix = os.path.join(logic.activeProject.properties.runningFolder, f"mcp-nmap-{int(time.time())}")
            nmap_xml = run_nmap_scan(
                target,
                output_prefix,
                discovery=True,
                staged=False
            )

            # Import nmap XML results into the project
            if nmap_xml and os.path.isfile(nmap_xml):
                nmapImporter = NmapImporter(None, hostRepository)
                nmapImporter.setDB(logic.activeProject.database)
                nmapImporter.setHostRepository(hostRepository)
                nmapImporter.setFilename(nmap_xml)
                nmapImporter.setOutput("")
                nmapImporter.run()
            else:
                return {
                    "target": target,
                    "error": "Nmap scan failed or produced no XML output",
                    "debug_info": debug_info
                }

            # Gather structured results from the project
            hosts = hostRepository.getAllHostObjs()
            results = []
            for host in hosts:
                host_dict = host.__dict__.copy()
                host_dict.pop('_sa_instance_state', None)
                # Ports/services for this host
                try:
                    ports = logic.activeProject.repositoryContainer.portRepository.getPortsByHostId(host.id)
                except Exception:
                    ports = []
                ports_data = []
                for port in ports:
                    port_dict = port.__dict__.copy()
                    port_dict.pop('_sa_instance_state', None)
                    # Service for this port
                    try:
                        service = (
                            logic.activeProject.repositoryContainer.serviceRepository.getServiceById(port.serviceId)
                            if hasattr(port, 'serviceId') and port.serviceId
                            else None
                        )
                    except Exception:
                        service = None
                    if service:
                        service_dict = service.__dict__.copy()
                        service_dict.pop('_sa_instance_state', None)
                        port_dict['service'] = service_dict
                    ports_data.append(port_dict)
                host_dict['ports'] = ports_data
                results.append(host_dict)

            return {
                "target": target,
                "results": results,
                "debug_info": debug_info
            }
        except Exception as e:
            return {
                "target": arguments.get("target", "localhost"),
                "error": str(e),
                "debug_info": debug_info
            }

    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        if request.get("method") == "list_tools":
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": [
                    {
                        "name": name,
                        "description": tool["description"],
                        "inputSchema": tool["inputSchema"],
                    }
                    for name, tool in self.tools.items()
                ],
            }
        elif request.get("method") == "call_tool":
            tool_name = request.get("params", {}).get("name")
            arguments = request.get("params", {}).get("arguments", {})
            if tool_name in self.tools:
                result = await self.tools[tool_name]["handler"](arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": result,
                }
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {"code": -32601, "message": "Tool not found"},
                }
        else:
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": -32601, "message": "Method not found"},
            }

    async def run(self):
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                request = json.loads(line.decode())
                response = await self.handle_request(request)
                print(json.dumps(response), flush=True)
            except Exception as e:
                error_response = {
                    "jsonrpc": "2.0",
                    "id": request.get("id") if 'request' in locals() else None,
                    "error": {"code": -32000, "message": str(e)},
                }
                print(json.dumps(error_response), flush=True)

if __name__ == "__main__":
    server = MCPServer()
    asyncio.run(server.run())
