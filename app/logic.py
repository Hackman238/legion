#!/usr/bin/env python

"""
LEGION (https://govanguard.io)
Copyright (c) 2018 GoVanguard

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
    version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
    details.

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <http://www.gnu.org/licenses/>.
"""

import ntpath
import shutil
import tempfile

from app.shell.Shell import Shell
from db.database import *
from db.repositories.CVERepository import CVERepository
from db.repositories.HostRepository import HostRepository
from db.repositories.PortRepository import PortRepository
from db.repositories.ProcessRepository import ProcessRepository
from db.repositories.ServiceRepository import ServiceRepository
from parsers.Parser import *
from scripts.python import pyShodan
from ui.ancillaryDialog import *


class Logic:
    def __init__(self, project_name: str, db: Database, shell: Shell):
        self.shell = shell
        self.db = db
        self.cwd = shell.get_current_working_directory()
        self.projectname = project_name
        log.info(project_name)
        self.createTemporaryFiles()  # creates temporary files/folders used by SPARTA
        self.service_repository: ServiceRepository = ServiceRepository(self.db)
        self.process_repository: ProcessRepository = ProcessRepository(self.db, log)
        self.host_repository: HostRepository = HostRepository(self.db)
        self.port_repository: PortRepository = PortRepository(self.db)
        self.cve_repository: CVERepository = CVERepository(self.db)

    def createTemporaryFiles(self):
        try:
            log.info('Creating temporary files..')
            self.istemp = True                                          # indicates that file is temporary and can be deleted if user exits without saving
            log.info(self.cwd)

            self.outputfolder = self.shell.create_temporary_directory(
                prefix="legion-", suffix="-tool-output", directory="./tmp/")  # to store tool output of finished processes
            self.runningfolder = self.shell.create_temporary_directory(
                prefix="legion-", suffix="-running", directory="./tmp/")  # to store tool output of running processes

            self.shell.create_directory_recursively(f"{self.outputfolder}/screenshots")  # to store screenshots
            self.shell.create_directory_recursively(f"{self.runningfolder}/nmap")  # to store nmap output
            self.shell.create_directory_recursively(f"{self.runningfolder}/hydra")  # to store hydra output
            self.shell.create_directory_recursively(f"{self.runningfolder}/dnsmap")  # to store dnsmap output

            self.usernamesWordlist = Wordlist(self.outputfolder + '/legion-usernames.txt')  # to store found usernames
            self.passwordsWordlist = Wordlist(self.outputfolder + '/legion-passwords.txt')  # to store found passwords
        except:
            log.info('Something went wrong creating the temporary files..')
            log.info("Unexpected error: {0}".format(sys.exc_info()[0]))

    def removeTemporaryFiles(self):
        log.info('Removing temporary files and folders..')
        try:
            # if current project is not temporary & delete wordlists if necessary
            if not self.istemp and not self.storeWordlists:
                log.info('Removing wordlist files.')
                self.shell.remove_file(self.usernamesWordlist.filename)
                self.shell.remove_file(self.passwordsWordlist.filename)
            else:
                self.shell.remove_file(self.projectname)
                self.shell.remove_directory(self.outputfolder)

            self.shell.remove_directory(self.runningfolder)
        except:
            log.info('Something went wrong removing temporary files and folders..')
            log.info("Unexpected error: {0}".format(sys.exc_info()[0]))

    def createFolderForTool(self, tool):
        if 'nmap' in tool:
            tool = 'nmap'
        path = self.runningfolder+'/'+re.sub("[^0-9a-zA-Z]", "", str(tool))
        if not os.path.exists(path):
            os.makedirs(path)

    # this flag is matched to the conf file setting, so that we know if we need to delete the found usernames/passwords wordlists on exit
    def setStoreWordlistsOnExit(self, flag=True):
        self.storeWordlists = flag

    # this function moves the specified tool output file from the temporary 'running' folder to the 'tool output' folder
    def moveToolOutput(self, outputFilename):
        try:
            # first create the tool folder if it doesn't already exist
            tool = ntpath.basename(ntpath.dirname(str(outputFilename)))
            path = self.outputfolder+'/'+str(tool)
            if not os.path.exists(str(path)):
                os.makedirs(str(path))
            
            # check if the outputFilename exists, if not try .xml and .txt extensions (different tools use different formats)
            if os.path.exists(str(outputFilename)) and os.path.isfile(str(outputFilename)):
                shutil.move(str(outputFilename), str(path))
            # move all the nmap files (not only the .xml)
            elif os.path.exists(str(outputFilename)+'.xml') and os.path.exists(str(outputFilename)+'.nmap') and os.path.exists(str(outputFilename)+'.gnmap') and os.path.isfile(str(outputFilename)+'.xml') and os.path.isfile(str(outputFilename)+'.nmap') and os.path.isfile(str(outputFilename)+'.gnmap'):
                try:
                    exportNmapToHTML(str(outputFilename))
                    shutil.move(str(outputFilename)+'.html', str(path))
                except:
                    pass

                shutil.move(str(outputFilename)+'.xml', str(path))
                shutil.move(str(outputFilename)+'.nmap', str(path))
                shutil.move(str(outputFilename)+'.gnmap', str(path))
            elif os.path.exists(str(outputFilename)+'.xml') and os.path.isfile(str(outputFilename)+'.xml'):
                shutil.move(str(outputFilename)+'.xml', str(path))
            elif os.path.exists(str(outputFilename)+'.txt') and os.path.isfile(str(outputFilename)+'.txt'):
                shutil.move(str(outputFilename)+'.txt', str(path))                          
        except:
            log.info('Something went wrong moving the tool output file..')
            log.info("Unexpected error: {0}".format(sys.exc_info()[0]))

    def copyNmapXMLToOutputFolder(self, file):
        try:
            path = self.outputfolder+"/nmap"
            filename = ntpath.basename(str(file))
            if not os.path.exists(str(path)):
                os.makedirs(str(path))

            shutil.copy(str(file), str(path))   # will overwrite if file already exists
        except:
            log.info('Something went wrong copying the imported XML to the project folder.')
            log.info("Unexpected error: {0}".format(sys.exc_info()[0]))

    def openExistingProject(self, filename, projectType="legion"):
        try:
            log.info('Opening project..')
            self.istemp = False                                         # indicate the file is NOT temporary and should NOT be deleted later
            
            self.projectname = str(filename)                            # set the new projectname and outputfolder vars
            nameOffset = len(projectType) + 1
            if not str(filename).endswith(projectType):         
                self.outputfolder = str(filename)+'-tool-output'        # use the same name as the file for the folder (without the extension)
            else:
                self.outputfolder = str(filename)[:-nameOffset]+'-tool-output'

            self.usernamesWordlist = Wordlist(self.outputfolder + '/' + projectType + '-usernames.txt')          # to store found usernames
            self.passwordsWordlist = Wordlist(self.outputfolder + '/' + projectType + '-passwords.txt')          # to store found passwords          
            
            self.runningfolder = tempfile.mkdtemp(suffix = "-running", prefix = projectType + '-')               # to store tool output of running processes
            self.db = Database(self.projectname)                        # use the new db
            self.cwd = ntpath.dirname(str(self.projectname))+'/'        # update cwd so it appears nicely in the window title
        
        except:
            log.info('Something went wrong while opening the project..')
            log.info("Unexpected error: {0}".format(sys.exc_info()[0]))
        
    # this function copies the current project files and folder to a new location
    # if the replace flag is set to 1, it overwrites the destination file and folder
    def saveProjectAs(self, filename, replace=0, projectType = 'legion'):
        try:
            # the folder name must be : filename-tool-output (without the .legion extension)
            nameOffset = len(projectType) + 1
            if not str(filename).endswith(projectType):
                foldername = str(filename)+'-tool-output'
                filename = str(filename) + '.legion'
            else:
                foldername = filename[:-nameOffset]+'-tool-output'

            # check if filename already exists (skip the check if we want to replace the file)
            if replace == 0 and os.path.exists(str(filename)) and os.path.isfile(str(filename)):
                return False

            shutil.copyfile(self.projectname, str(filename))
            os.system('cp -r "'+self.outputfolder+'/." "'+str(foldername)+'"')
            
            if self.istemp:                                             # we can remove the temp file/folder if it was temporary
                log.info('Removing temporary files and folders..')
                os.remove(self.projectname)
                shutil.rmtree(self.outputfolder)

            self.db.openDB(str(filename))                               # inform the DB to use the new file
            self.cwd = ntpath.dirname(str(filename))+'/'                # update cwd so it appears nicely in the window title
            self.projectname = str(filename)
            self.outputfolder = str(foldername)

            self.usernamesWordlist = Wordlist(self.outputfolder + '/legion-usernames.txt')          # to store found usernames
            self.passwordsWordlist = Wordlist(self.outputfolder + '/legion-passwords.txt')          # to store found passwords  
            
            self.istemp = False                                         # indicate that file is NOT temporary anymore and should NOT be deleted later
            return True

        except:
            log.info('Something went wrong while saving the project..')
            log.info("Unexpected error: {0}".format(sys.exc_info()[0]))
            return False

    # get notes for given host IP
    def getNoteFromDB(self, hostId):
        session = self.db.session()
        return session.query(note).filter_by(hostId=str(hostId)).first()

    # get script info for given host IP
    def getScriptsFromDB(self, hostIP):
        query = ('SELECT host.id, host.scriptId, port.portId, port.protocol FROM l1ScriptObj AS host ' +
                 'INNER JOIN hostObj AS hosts ON hosts.id = host.hostId ' +
                 'LEFT OUTER JOIN portObj AS port ON port.id = host.portId ' +
                 'WHERE hosts.ip=?')

        return self.db.metadata.bind.execute(query, str(hostIP)).fetchall()
        
    def getScriptOutputFromDB(self, scriptDBId):
        query = ('SELECT script.output FROM l1ScriptObj as script WHERE script.id = ?')
        return self.db.metadata.bind.execute(query, str(scriptDBId)).fetchall()

    # used to delete all port/script data related to a host - to overwrite portscan info with the latest scan   
    def deleteAllPortsAndScriptsForHostFromDB(self, hostID, protocol):
        session = self.db.session()
        ports_for_host = session.query(portObj).filter(portObj.hostId == hostID).filter(portObj.protocol == str(protocol)).all()
        for p in ports_for_host:
            scripts_for_ports = session.query(l1ScriptObj).filter(l1ScriptObj.portId == p.id).all()
            for s in scripts_for_ports:
                session.delete(s)
        for p in ports_for_host:
            session.delete(p)
        session.commit()
        return

    def deleteHost(self, hostIP):
        session = self.db.session()
        h = session.query(hostObj).filter_by(ip=str(hostIP)).first()
        session.delete(h)
        session.commit()
        return

    # this function returns all the processes from the DB
    # the showProcesses flag is used to ensure we don't display processes in the process table after we have cleared them or when an existing project is opened.
    # to speed up the queries we replace the columns we don't need by zeros (the reason we need all the columns is we are using the same model to display process information everywhere)
    def getProcessesFromDB(self, filters, showProcesses='noNmap', sort = 'desc', ncol = 'id'):
        if showProcesses == 'noNmap':                                         # we do not fetch nmap processes because these are not displayed in the host tool tabs / tools
            query = ('SELECT "0", "0", "0", process.name, "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0" FROM process AS process WHERE process.closed="False" AND process.name!="nmap" group by process.name')
            result = self.db.metadata.bind.execute(query).fetchall()

        elif showProcesses == False:                                    # when opening a project, fetch only the processes that have display=false and were not in tabs that were closed by the user
            query = ('SELECT process.id, process.hostIp, process.tabTitle, process.outputfile, output.output FROM process AS process '
            'INNER JOIN process_output AS output ON process.id = output.processId '
            'WHERE process.display=? AND process.closed="False" order by process.id desc')
            result = self.db.metadata.bind.execute(query, str(showProcesses)).fetchall()

            #query = ('SELECT process.id, process.hostIp, process.tabTitle, process.outputfile, output.output FROM process AS process '
            #'INNER JOIN process_output AS output ON process.id = output.processId '
            #'WHERE process.display=? AND process.closed="False" order by process.id desc')

        else:                                                           # show all the processes in the (bottom) process table (no matter their closed value)
            query = ('SELECT * FROM process AS process WHERE process.display=? order by {0} {1}'.format(ncol, sort))
            result = self.db.metadata.bind.execute(query, str(showProcesses)).fetchall()

        return result

    def getHostsForTool(self, toolname, closed='False'):
        if closed == 'FetchAll':
            query = ('SELECT "0", "0", "0", "0", "0", process.hostIp, process.port, process.protocol, "0", "0", process.outputfile, "0", "0", "0" FROM process AS process WHERE process.name=?')
        else:
            query = ('SELECT process.id, "0", "0", "0", "0", "0", "0", process.hostIp, process.port, process.protocol, "0", "0", process.outputfile, "0", "0", "0" FROM process AS process WHERE process.name=? and process.closed="False"')
            
        return self.db.metadata.bind.execute(query, str(toolname)).fetchall()

    def toggleHostCheckStatus(self, ipaddr):
        session = self.db.session()
        h = session.query(hostObj).filter_by(ip=ipaddr).first()
        if h:
            if h.checked == 'False':
                h.checked = 'True'
            else:
                h.checked = 'False'
            session.add(h)
            self.db.commit()

    # this function adds a new process to the DB
    def addProcessToDB(self, proc):
        log.info('Add process')
        p_output = process_output()                                     # add row to process_output table (separate table for performance reasons)
        p = process(str(proc.pid()), str(proc.name), str(proc.tabTitle), str(proc.hostIp), str(proc.port), str(proc.protocol), unicode(proc.command), proc.startTime, "", str(proc.outputfile), 'Waiting', [p_output], 100, 0)
        log.info(p)
        session = self.db.session()
        session.add(p)
        self.db.commit()
        proc.id = p.id
        return p.id
    
    def addScreenshotToDB(self, ip, port, filename):
        p_output = process_output()                                     # add row to process_output table (separate table for performance reasons)
        p = process(0, "screenshooter", "screenshot ("+str(port)+"/tcp)", str(ip), str(port), "tcp", "", getTimestamp(True), getTimestamp(True), str(filename), "Finished", [p_output], 2, 0)
        session = self.db.session()
        session.add(p)
        session.commit()
        return p.id

    # is not actually a toggle function. it sets all the non-running processes display flag to false to ensure they aren't shown in the process table
    # but they need to be shown as tool tabs. this function is called when a user clears the processes or when a project is being closed.
    def toggleProcessDisplayStatus(self, resetAll=False):
        session = self.db.session()
        proc = session.query(process).filter_by(display='True').all()
        for p in proc:
            session.add(self.toggle_process_status_field(p, resetAll))
        self.db.commit()

    def toggle_process_status_field(self, p, reset_all):
        not_running = p.status != 'Running'
        not_waiting = p.status != 'Waiting'

        if reset_all and not_running:
            p.display = 'False'
        else:
            if not_running and not_waiting:
                p.display = 'False'

        return p

    # this function updates the status of a process if it is killed
    def storeProcessKillStatusInDB(self, procId):
        session = self.db.session()
        proc = session.query(process).filter_by(id=procId).first()
        #proc = process.query.filter_by(id=procId).first()
        if proc and not proc.status == 'Finished':
            proc.status = 'Killed'
            proc.endTime = getTimestamp(True)   # store end time
            session.add(proc)
            #session.commit()
            self.db.commit()

    def storeProcessCrashStatusInDB(self, procId):
        session = self.db.session()
        proc = session.query(process).filter_by(id=procId).first()
        #proc = process.query.filter_by(id=procId).first()
        if proc and not proc.status == 'Killed' and not proc.status == 'Cancelled':
            proc.status = 'Crashed'
            proc.endTime = getTimestamp(True)   # store end time
            session.add(proc)
            #session.commit()
            self.db.commit()
            
    # this function updates the status of a process if it is killed
    def storeProcessCancelStatusInDB(self, procId):
        session = self.db.session()
        proc = session.query(process).filter_by(id=procId).first()
        #proc = process.query.filter_by(id=procId).first()
        if proc:
            proc.status = 'Cancelled'
            proc.endTime = getTimestamp(True)   # store end time
            session.add(proc)
            #session.commit()
            self.db.commit()

    def storeProcessRunningStatusInDB(self, procId, pid):
        session = self.db.session()
        proc = session.query(process).filter_by(id=procId).first()
        #proc = process.query.filter_by(id=procId).first()
        if proc:
            proc.status = 'Running'
            proc.pid = str(pid)
            session.add(proc)
            #session.commit()
            self.db.commit()

    # change the status in the db as closed
    def storeCloseTabStatusInDB(self, procId):
        session = self.db.session()
        proc = session.query(process).filter_by(id=procId).first()
        #proc = process.query.filter_by(id=int(procId)).first()
        if proc:
            proc.closed = 'True'
            session.add(proc)
            #session.commit()
            self.db.commit()

    # change the status in the db as closed
    def storeProcessRunningElapsedInDB(self, procId, elapsed):
        session = self.db.session()
        proc = session.query(process).filter_by(id=procId).first()
        if proc:
            proc.elapsed = elapsed
            session.add(proc)
            self.db.commit()

    def storeNotesInDB(self, hostId, notes):
        if len(notes) == 0:
            notes = unicode("".format(hostId=hostId))
        log.debug("Storing notes for {hostId}, Notes {notes}".format(hostId=hostId, notes=notes))
        t_note = self.getNoteFromDB(hostId)
        if t_note:
            t_note.text = unicode(notes)
        else:
            t_note = note(hostId, unicode(notes))
        session = self.db.session()
        session.add(t_note)
        self.db.commit()


class PythonImporter(QtCore.QThread):
    tick = QtCore.pyqtSignal(int, name="changed")                       # New style signal
    done = QtCore.pyqtSignal(name="done")                               # New style signal
    schedule = QtCore.pyqtSignal(object, bool, name="schedule")         # New style signal
    log = QtCore.pyqtSignal(str, name="log")

    def __init__(self):
        QtCore.QThread.__init__(self, parent=None)
        self.output = ''
        self.hostIp = ''
        self.pythonScriptDispatch = {'pyShodan': pyShodan.PyShodanScript()}
        self.pythonScriptObj = None
        self.importProgressWidget = ProgressWidget('Importing shodan data..')

    def tsLog(self, msg):
        self.log.emit(str(msg))

    def setDB(self, db):
        self.db = db

    def setHostIp(self, hostIp):
        self.hostIp = hostIp

    def setPythonScript(self, pythonScript):
        self.pythonScriptObj = self.pythonScriptDispatch[pythonScript]

    def setOutput(self, output):
        self.output = output

    def run(self):                                                      # it is necessary to get the qprocess because we need to send it back to the scheduler when we're done importing
        try:
            session = self.db.session()
            startTime = time()
            self.db.dbsemaphore.acquire()                               # ensure that while this thread is running, no one else can write to the DB
            #self.setPythonScript(self.pythonScript)
            db_host = session.query(hostObj).filter_by(ip = self.hostIp).first()
            self.pythonScriptObj.setDbHost(db_host)
            self.pythonScriptObj.setSession(session)
            self.pythonScriptObj.run()
            session.commit()
            self.db.dbsemaphore.release()                               # we are done with the DB
            self.tsLog('Finished in ' + str(time() - startTime) + ' seconds.')
            self.done.emit()

        except Exception as e:
            self.tsLog(e)
            raise
            self.done.emit()


class NmapImporter(QtCore.QThread):
    tick = QtCore.pyqtSignal(int, name="changed")                       # New style signal
    done = QtCore.pyqtSignal(name="done")                               # New style signal
    schedule = QtCore.pyqtSignal(object, bool, name="schedule")         # New style signal
    log = QtCore.pyqtSignal(str, name="log")

    def __init__(self):
        QtCore.QThread.__init__(self, parent=None)
        self.output = ''
        self.importProgressWidget = ProgressWidget('Importing nmap..')

    def tsLog(self, msg):
        self.log.emit(str(msg))

    def setDB(self, db):
        self.db = db

    def setFilename(self, filename):
        self.filename = filename
        
    def setOutput(self, output):
        self.output = output

    def run(self):  # it is necessary to get the qprocess because we need to send it back to the scheduler when we're done importing
        try:
            self.importProgressWidget.show()
            session = self.db.session()
            self.tsLog("Parsing nmap xml file: " + self.filename)
            startTime = time()
            
            try:
                parser = Parser(self.filename)
            except:
                self.tsLog('Giving up on import due to previous errors.')
                self.tsLog("Unexpected error: {0}".format(sys.exc_info()[0]))
                self.done.emit()
                return
                
            self.db.dbsemaphore.acquire()                               # ensure that while this thread is running, no one else can write to the DB
            s = parser.getSession()                                    # nmap session info
            if s:
                n = nmapSessionObj(self.filename, s.startTime, s.finish_time, s.nmapVersion, s.scanArgs, s.totalHosts, s.upHosts, s.downHosts)
                session.add(n)
            hostCount = len(parser.getAllHosts())
            if hostCount==0:                                            # to fix a division by zero if we ran nmap on one host
                hostCount=1
            totalprogress = 0

            self.importProgressWidget.setProgress(int(totalprogress))
            self.importProgressWidget.show()
   
            createProgress = 0 
            createOsNodesProgress = 0
            createPortsProgress = 0

            for h in parser.getAllHosts():                                # create all the hosts that need to be created
                db_host = session.query(hostObj).filter_by(ip=h.ip).first()
                
                if not db_host:                                         # if host doesn't exist in DB, create it first
                    hid = hostObj(osMatch='', osAccuracy='', ip=h.ip, ipv4=h.ipv4, ipv6=h.ipv6, macaddr=h.macaddr, status=h.status, hostname=h.hostname, vendor=h.vendor, uptime=h.uptime, lastboot=h.lastboot, distance=h.distance, state=h.state, count=h.count)
                    self.tsLog("Adding db_host")
                    session.add(hid)
                    t_note = note(h.ip, 'Added by nmap')
                    session.add(t_note)
                else:
                    self.tsLog("Found db_host already in db")

                createProgress = createProgress + ((100.0 / hostCount) / 5)
                totalprogress = totalprogress + createProgress
                self.importProgressWidget.setProgress(int(totalprogress))
                self.importProgressWidget.show()

            session.commit()
            
            for h in parser.getAllHosts():                                # create all OS, service and port objects that need to be created
                self.tsLog("Processing h {ip}".format(ip=h.ip))

                db_host = session.query(hostObj).filter_by(ip=h.ip).first()
                if db_host:
                    self.tsLog("Found db_host during os/ports/service processing")
                else:
                    self.log("Did not find db_host during os/ports/service processing")
                
                os_nodes = h.getOs()                                   # parse and store all the OS nodes
                self.tsLog("    'os_nodes' to process: {os_nodes}".format(os_nodes=str(len(os_nodes))))
                for os in os_nodes:
                    self.tsLog("    Processing os obj {os}".format(os=str(os.name)))
                    db_os = session.query(osObj).filter_by(hostId=db_host.id).filter_by(name=os.name).filter_by(family=os.family).filter_by(generation=os.generation).filter_by(osType=os.osType).filter_by(vendor=os.vendor).first()
                    
                    if not db_os:
                        t_osObj = osObj(os.name, os.family, os.generation, os.osType, os.vendor, os.accuracy, db_host.id)
                        session.add(t_osObj)

                    createOsNodesProgress = createOsNodesProgress + ((100.0 / hostCount) / 5)
                    totalprogress = totalprogress + createOsNodesProgress
                    self.importProgressWidget.setProgress(int(totalprogress))
                    self.importProgressWidget.show()

                session.commit()

                all_ports = h.all_ports()
                self.tsLog("    'ports' to process: {all_ports}".format(all_ports=str(len(all_ports))))
                for p in all_ports:                                 # parse the ports
                    self.tsLog("        Processing port obj {port}".format(port=str(p.portId)))
                    s = p.getService()

                    if not (s is None):                                 # check if service already exists to avoid adding duplicates
                        #print("            Found service {service} for port {port}".format(service=str(s.name),port=str(p.portId)))
                        #db_service = session.query(serviceObj).filter_by(name=s.name).filter_by(product=s.product).filter_by(version=s.version).filter_by(extrainfo=s.extrainfo).filter_by(fingerprint=s.fingerprint).first()
                        db_service = session.query(serviceObj).filter_by(name=s.name).first()
                        if not db_service:
                            #print("Did not find service *********** name={0} prod={1} ver={2} extra={3} fing={4}".format(s.name, s.product, s.version, s.extrainfo, s.fingerprint))
                            db_service = serviceObj(s.name, s.product, s.version, s.extrainfo, s.fingerprint)
                            session.add(db_service)
                       # else:
                            #print("FOUND service *************** name={0}".format(db_service.name))

                    else:                                               # else, there is no service info to parse
                        db_service = None                   
                                                                        # fetch the port
                    db_port = session.query(portObj).filter_by(hostId=db_host.id).filter_by(portId=p.portId).filter_by(protocol=p.protocol).first()
                    
                    if not db_port:     
                        #print("Did not find port *********** portid={0} proto={1}".format(p.portId, p.protocol))
                        if db_service:
                            db_port = portObj(p.portId, p.protocol, p.state, db_host.id, db_service.id)
                        else:
                            db_port = portObj(p.portId, p.protocol, p.state, db_host.id, '')
                        session.add(db_port)
                    #else:
                        #print('FOUND port *************** portid={0}'.format(db_port.portId))
                    createPortsProgress = createPortsProgress + ((100.0 / hostCount) / 5)
                    totalprogress = totalprogress + createPortsProgress
                    self.importProgressWidget.setProgress(totalprogress)
                    self.importProgressWidget.show()

            session.commit()
            
            #totalprogress += progress
            #self.tick.emit(int(totalprogress))

            for h in parser.getAllHosts():                                # create all script objects that need to be created
                db_host = session.query(hostObj).filter_by(ip=h.ip).first()
                
                for p in h.all_ports():
                    for scr in p.getScripts():
                        self.tsLog("        Processing script obj {scr}".format(scr=str(scr)))                             
                        print("        Processing script obj {scr}".format(scr=str(scr)))
                        db_port = session.query(portObj).filter_by(hostId=db_host.id).filter_by(portId=p.portId).filter_by(protocol=p.protocol).first()
                        db_script = session.query(l1ScriptObj).filter_by(scriptId=scr.scriptId).filter_by(portId=db_port.id).first()

                        if not db_script:                               # if this script object doesn't exist, create it
                            t_l1ScriptObj = l1ScriptObj(scr.scriptId, scr.output, db_port.id, db_host.id)
                            self.tsLog("        Adding l1ScriptObj obj {script}".format(script=scr.scriptId))
                            session.add(t_l1ScriptObj)
                    
                for hs in h.getHostScripts():
                    db_script = session.query(l1ScriptObj).filter_by(scriptId=hs.scriptId).filter_by(hostId=db_host.id).first()
                    if not db_script:
                        t_l1ScriptObj = l1ScriptObj(hs.scriptId, hs.output, None, db_host.id)                  
                        session.add(t_l1ScriptObj)
                    
            session.commit()
                    
            for h in parser.getAllHosts():                                # update everything

                db_host = session.query(hostObj).filter_by(ip=h.ip).first()
                
                if db_host.ipv4 == '' and not h.ipv4 == '':
                    db_host.ipv4 = h.ipv4
                if db_host.ipv6 == '' and not h.ipv6 == '':
                    db_host.ipv6 = h.ipv6
                if db_host.macaddr == '' and not h.macaddr == '':
                    db_host.macaddr = h.macaddr
                if not h.status == '':
                    db_host.status = h.status
                if db_host.hostname == '' and not h.hostname == '':
                    db_host.hostname = h.hostname
                if db_host.vendor == '' and not h.vendor == '':
                    db_host.vendor = h.vendor
                if db_host.uptime == '' and not h.uptime == '':
                    db_host.uptime = h.uptime
                if db_host.lastboot == '' and not h.lastboot == '':
                    db_host.lastboot = h.lastboot
                if db_host.distance == '' and not h.distance == '':
                    db_host.distance = h.distance
                if db_host.state == '' and not h.state == '':
                    db_host.state = h.state
                if db_host.count == '' and not h.count == '':
                    db_host.count = h.count

                session.add(db_host)
                        
                tmp_name = ''
                tmp_accuracy = '0'                                      # TODO: check if better to convert to int for comparison
                
                os_nodes = h.getOs()
                for os in os_nodes:
                    db_os = session.query(osObj).filter_by(hostId=db_host.id).filter_by(name=os.name).filter_by(family=os.family).filter_by(generation=os.generation).filter_by(osType=os.osType).filter_by(vendor=os.vendor).first()
                    
                    db_os.osAccuracy = os.accuracy                     # update the accuracy
                            
                    if not os.name == '':                               # get the most accurate OS match/accuracy to store it in the host table for easier access
                        if os.accuracy > tmp_accuracy:
                            tmp_name = os.name
                            tmp_accuracy = os.accuracy

                if os_nodes:                                            # if there was operating system info to parse
                    
                    if not tmp_name == '' and not tmp_accuracy == '0':  # update the current host with the most accurate OS match
                        db_host.osMatch = tmp_name
                        db_host.osAccuracy = tmp_accuracy

                session.add(db_host)

                for scr in h.getHostScripts():
                    print("-----------------------Host SCR: {0}".format(scr.scriptId))
                    db_host = session.query(hostObj).filter_by(ip=h.ip).first()
                    scrProcessorResults = scr.scriptSelector(db_host)
                    for scrProcessorResult in scrProcessorResults:
                        session.add(scrProcessorResult)

                for scr in h.getScripts():
                    print("-----------------------SCR: {0}".format(scr.scriptId))
                    db_host = session.query(hostObj).filter_by(ip=h.ip).first()
                    scrProcessorResults = scr.scriptSelector(db_host)
                    for scrProcessorResult in scrProcessorResults:
                        session.add(scrProcessorResult)
                                
                for p in h.all_ports():     
                    s = p.getService()
                    if not (s is None):
                        #db_service = session.query(serviceObj).filter_by(name=s.name).filter_by(product=s.product).filter_by(version=s.version).filter_by(extrainfo=s.extrainfo).filter_by(fingerprint=s.fingerprint).first()
                        db_service = session.query(serviceObj).filter_by(name=s.name).first()
                    else:
                        db_service = None                       
                                                                        # fetch the port
                    db_port = session.query(portObj).filter_by(hostId=db_host.id).filter_by(portId=p.portId).filter_by(protocol=p.protocol).first()
                    if db_port:
                        #print("************************ Found {0}".format(db_port))

                        if db_port.state != p.state:
                            db_port.state = p.state
                            session.add(db_port)
                    
                        if not (db_service is None) and db_port.serviceId != db_service.id:                        # if there is some new service information, update it
                            db_port.serviceId = db_service.id
                            session.add(db_port)
                
                    for scr in p.getScripts():                         # store the script results (note that existing script outputs are also kept)    
                        db_script = session.query(l1ScriptObj).filter_by(scriptId=scr.scriptId).filter_by(portId=db_port.id).first()

                        if not scr.output == '' and scr.output is not None:
                            db_script.output = scr.output

                        session.add(db_script)
                
            totalprogress = 100
            self.importProgressWidget.setProgress(int(totalprogress))
            self.importProgressWidget.show()

            session.commit()
            self.db.dbsemaphore.release()                               # we are done with the DB
            self.tsLog('Finished in '+ str(time()-startTime) + ' seconds.')
            self.done.emit()
            self.importProgressWidget.hide()
            self.schedule.emit(parser, self.output == '')               # call the scheduler (if there is no terminal output it means we imported nmap)
            
        except Exception as e:
            self.tsLog('Something went wrong when parsing the nmap file..')
            self.tsLog("Unexpected error: {0}".format(sys.exc_info()[0]))
            self.tsLog(e)
            raise
            self.done.emit()
