"""
LEGION (https://shanewilliamscott.com)
Copyright (c) 2025 Shane William Scott

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
    version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
    details.

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <http://www.gnu.org/licenses/>.

Author(s): Shane Scott (sscott@shanewilliamscott.com), Dmitriy Dubson (d.dubson@gmail.com)
"""
import sys

from PyQt6 import QtCore

from app.actions.updateProgress import AbstractUpdateProgressObservable
from app.logging.legionLog import getAppLogger
from db.entities.host import hostObj
from db.entities.l1script import l1ScriptObj
from db.entities.nmapSession import nmapSessionObj
from db.entities.note import note
from db.entities.os import osObj
from db.entities.port import portObj
from db.entities.service import serviceObj
from db.repositories.HostRepository import HostRepository
from parsers.Parser import parseNmapReport, MalformedXmlDocumentException
from time import time

appLog = getAppLogger()

class NmapImporter(QtCore.QThread):
    tick = QtCore.pyqtSignal(int, name="changed")  # New style signal
    done = QtCore.pyqtSignal(name="done")  # New style signal
    schedule = QtCore.pyqtSignal(object, bool, name="schedule")  # New style signal
    log = QtCore.pyqtSignal(str, name="log")
    progressUpdated = QtCore.pyqtSignal(int, str)  # progress, title

    def __init__(self, updateProgressObservable: AbstractUpdateProgressObservable, hostRepository: HostRepository):
        QtCore.QThread.__init__(self, parent=None)
        self.output = ''
        self.updateProgressObservable = updateProgressObservable
        self.hostRepository = hostRepository
        self._cancel_requested = False  # Cancellation flag

    def cancel(self):
        self._cancel_requested = True

    # Removed startProgressTimer and stopProgressTimer (QTimer usage) due to threading issues.

    def updatePercentFromXml(self):
        """Read the XML file and update percent in the process table."""
        appLog.debug("updatePercentFromXml called")
        self.tsLog("[DEBUG] updatePercentFromXml called")
        try:
            if hasattr(self, "filename") and hasattr(self, "processId") and self.processId:
                appLog.debug(f"updatePercentFromXml: filename={self.filename}, processId={self.processId}")
                self.tsLog(f"[DEBUG] updatePercentFromXml: filename={self.filename}, processId={self.processId}")
                from parsers.Parser import parseNmapReport
                nmapReport = parseNmapReport(self.filename)
                highest_percent = nmapReport.get_highest_percent()
                if highest_percent is not None:
                    self.tsLog(f"[Periodic] Nmap scan percent complete: {highest_percent}%")
                    appLog.debug(f"[Periodic] Nmap scan percent complete: {highest_percent}%")
                    self.db.repositoryContainer.processRepository.storeProcessPercent(
                        self.processId, str(highest_percent)
                    )
                else:
                    self.tsLog("[Periodic] No percent found in XML.")
                    appLog.debug("[Periodic] No percent found in XML.")
        except Exception as e:
            self.tsLog(f"Periodic percent update failed: {e}")
            appLog.debug(f"Periodic percent update failed: {e}")

    def tsLog(self, msg):
        self.log.emit(str(msg))

    def setDB(self, db):
        self.db = db

    def setHostRepository(self, hostRepository: HostRepository):
        self.hostRepository = hostRepository

    def setFilename(self, filename):
        self.filename = filename

    def setOutput(self, output):
        self.output = output

    # it is necessary to get the qprocess because we need to send it back to the scheduler when we're done importing
    def run(self):
        try:
            # Removed periodic progress updates (QTimer) due to threading issues.
            if self.updateProgressObservable is not None:
                self.updateProgressObservable.start()
            session = self.db.session()
            self.tsLog("Parsing nmap xml file: " + self.filename)
            startTime = time()

            import os
            nmap_xml_path = self.filename
            try:
                nmapReport = parseNmapReport(nmap_xml_path)
            except (MalformedXmlDocumentException, FileNotFoundError) as e:
                # If file not found, try searching in any subdirectory of the parent directory
                if isinstance(e, FileNotFoundError):
                    parent_dir = os.path.dirname(nmap_xml_path)
                    base_name = os.path.basename(nmap_xml_path)
                    found = False
                    for sub in os.listdir(parent_dir):
                        sub_path = os.path.join(parent_dir, sub, base_name)
                        if os.path.isfile(sub_path):
                            self.tsLog(f"Found nmap xml in subdirectory: {sub_path}")
                            try:
                                nmapReport = parseNmapReport(sub_path)
                                found = True
                                break
                            except Exception as e2:
                                self.tsLog(f"Failed to parse nmap xml in subdirectory: {e2}")
                    if not found:
                        self.tsLog('Giving up on import due to previous errors.')
                        appLog.error(f"NMAP xml report is likely malformed or missing: {e}")
                        appLog.error(f"Nmap XML import failed: {e}")
                        self.updateProgressObservable.finished()
                        self.done.emit()
                        return
                else:
                    self.tsLog('Giving up on import due to previous errors.')
                    appLog.error(f"NMAP xml report is likely malformed: {e}")
                    appLog.error(f"Nmap XML import failed: {e}")
                    if self.updateProgressObservable is not None:
                        self.updateProgressObservable.finished()
                    self.done.emit()
                    return

            self.tsLog('nmap xml report read successfully!')
            self.db.dbsemaphore.acquire()  # ensure that while this thread is running, no one else can write to the DB
            s = nmapReport.getSession()  # nmap session info
            if s:
                # Log latest progress/ETA if available
                latest_progress = s.get_latest_progress()
                if latest_progress:
                    percent = latest_progress.get("percent")
                    remaining = latest_progress.get("remaining")
                    if percent is not None:
                        self.tsLog(f"Nmap scan percent complete: {percent}%")
                    elif remaining is not None:
                        self.tsLog(f"Nmap scan estimated time remaining: {remaining}")
                    else:
                        self.tsLog(f"Nmap scan progress: {latest_progress}")
                # After parsing, set percent to highest percent found in XML
                try:
                    highest_percent = nmapReport.get_highest_percent()
                    if hasattr(self, "processId") and self.processId and highest_percent is not None:
                        self.db.repositoryContainer.processRepository.storeProcessPercent(
                            self.processId, str(highest_percent)
                        )
                except Exception as e:
                    self.tsLog(f"Failed to set highest percent: {e}")
                n = nmapSessionObj(
                    self.filename, s.startTime, s.finish_time, s.nmapVersion, s.scanArgs, s.totalHosts,
                    s.upHosts, s.downHosts
                )
                try:
                    session.add(n)
                    session.commit()
                except Exception as e:
                    from sqlalchemy.exc import IntegrityError
                    if isinstance(e, IntegrityError):
                        msg = (
                            f"Duplicate nmap session for filename '{self.filename}' detected. "
                            "Skipping session insert."
                        )
                        self.tsLog(msg)
                        appLog.warning(msg)
                        session.rollback()
                    else:
                        raise

            allHosts = nmapReport.getAllHosts()
            hostCount = len(allHosts)
            if hostCount == 0:  # to fix a division by zero if we ran nmap on one host
                hostCount = 1

            createProgress = 0
            createOsNodesProgress = 0
            createPortsProgress = 0

            if self.updateProgressObservable is not None:
                self.updateProgressObservable.updateProgress(
                    int(createProgress), 'Adding hosts...'
                )
            self.progressUpdated.emit(0, 'Adding hosts...')

            last_update_time = time()
            update_interval = 1.0
            for h in allHosts:  # create all the hosts that need to be created
                if self._cancel_requested:
                    self.tsLog("Import canceled by user.")
                    if self.updateProgressObservable is not None:
                        self.updateProgressObservable.finished()
                    self.done.emit()
                    return

                db_host = self.hostRepository.getHostInformation(h.ip)

                if not db_host:  # if host doesn't exist in DB, create it first
                    hid = hostObj(
                        osMatch='', osAccuracy='', ip=h.ip, ipv4=h.ipv4, ipv6=h.ipv6, macaddr=h.macaddr,
                        status=h.status, hostname=h.hostname, vendor=h.vendor, uptime=h.uptime,
                        lastboot=h.lastboot, distance=h.distance, state=h.state, count=h.count
                    )
                    self.tsLog("Adding db_host")
                    session.add(hid)
                    session.commit()
                    t_note = note(h.ip, 'Added by nmap')
                    session.add(t_note)
                    session.commit()
                else:
                    self.tsLog("Found db_host already in db")

                createProgress = createProgress + (100.0 / hostCount)
                now = time()
                # Update progress at least every 1 second or on every host
                if (
                    self.updateProgressObservable is not None
                    and (now - last_update_time > update_interval or createProgress >= 100)
                ):
                    self.updateProgressObservable.updateProgress(
                        int(createProgress), 'Adding hosts...'
                    )
                    self.progressUpdated.emit(int(createProgress), 'Adding hosts...')
                    last_update_time = now

            if self.updateProgressObservable is not None:
                self.updateProgressObservable.updateProgress(
                    int(createOsNodesProgress), 'Creating Service, Port and OS children...'
                )
            self.progressUpdated.emit(0, 'Creating Service, Port and OS children...')

            last_update_time_os = time()
            update_interval_os = 1.0

            # --- Begin global port progress calculation ---
            # Calculate total number of ports across all hosts
            total_ports = sum(len(h.all_ports()) for h in allHosts)
            total_ports_processed = 0
            # --- End global port progress calculation ---

            for h in allHosts:  # create all OS, service and port objects that need to be created
                self.tsLog("Processing h {ip}".format(ip=h.ip))

                db_host = self.hostRepository.getHostInformation(h.ip)
                if db_host:
                    self.tsLog("Found db_host during os/ports/service processing")
                else:
                    self.tsLog("Did not find db_host during os/ports/service processing")
                    self.tsLog(
                        "A host that should have been found was not. Something is wrong. "
                        "Save your session and report a bug."
                    )
                    self.tsLog("Include your nmap file, sanitized if needed.")
                    continue

                os_nodes = h.getOs()  # parse and store all the OS nodes
                self.tsLog("    'os_nodes' to process: {os_nodes}".format(os_nodes=str(len(os_nodes))))
                for os in os_nodes:
                    self.tsLog("    Processing os obj {os}".format(os=str(os.name)))
                    db_os = session.query(osObj).filter_by(hostId=db_host.id).filter_by(name=os.name).filter_by(
                        family=os.family).filter_by(generation=os.generation).filter_by(osType=os.osType).filter_by(
                        vendor=os.vendor).first()

                    if not db_os:
                        t_osObj = osObj(
                            os.name, os.family, os.generation, os.osType, os.vendor, os.accuracy, db_host.id
                        )
                        session.add(t_osObj)
                        session.commit()

                createOsNodesProgress = createOsNodesProgress + (100.0 / hostCount)
                now_os = time()
                if (
                    self.updateProgressObservable is not None
                    and (now_os - last_update_time_os > update_interval_os or createOsNodesProgress >= 100)
                ):
                    self.updateProgressObservable.updateProgress(
                        int(createOsNodesProgress), 'Creating Service, Port and OS children...'
                    )
                    self.progressUpdated.emit(
                        int(createOsNodesProgress), 'Creating Service, Port and OS children...'
                    )
                    last_update_time_os = now_os

                # Only set to 0% at the start of all port processing
                if total_ports_processed == 0 and total_ports > 0:
                    if self.updateProgressObservable is not None:
                        self.updateProgressObservable.updateProgress(0, 'Processing ports...')
                    self.progressUpdated.emit(0, 'Processing ports...')
                last_update_time_ports = time()
                update_interval_ports = 1.0

                all_ports = h.all_ports()
                self.tsLog("    'ports' to process: {all_ports}".format(all_ports=str(len(all_ports))))
                for p in all_ports:  # parse the ports
                    if self._cancel_requested:
                        self.tsLog("Import canceled by user during port processing.")
                        if self.updateProgressObservable is not None:
                            self.updateProgressObservable.finished()
                        self.done.emit()
                        return

                    self.tsLog("        Processing port obj {port}".format(port=str(p.portId)))
                    s = p.getService()

                    if not (s is None):  # check if service already exists to avoid adding duplicates
                        self.tsLog(
                            "            Processing service result *********** "
                            "name={0} prod={1} ver={2} extra={3} fing={4}".format(
                                s.name, s.product, s.version, s.extrainfo, s.fingerprint
                            )
                        )
                        db_service = session.query(serviceObj).filter_by(hostId=db_host.id) \
                            .filter_by(name=s.name).filter_by(product=s.product).filter_by(version=s.version) \
                            .filter_by(extrainfo=s.extrainfo).filter_by(fingerprint=s.fingerprint).first()
                        if not db_service:
                            self.tsLog(
                                "            Did not find service *********** "
                                "name={0} prod={1} ver={2} extra={3} fing={4}".format(
                                    s.name, s.product, s.version, s.extrainfo, s.fingerprint
                                )
                            )
                            db_service = serviceObj(
                                s.name, db_host.id, s.product, s.version, s.extrainfo, s.fingerprint
                            )
                            session.add(db_service)
                            session.commit()
                    else:  # else, there is no service info to parse
                        db_service = None
                        # fetch the port
                    db_port = session.query(portObj).filter_by(hostId=db_host.id).filter_by(portId=p.portId) \
                        .filter_by(protocol=p.protocol).first()

                    if not db_port:
                        self.tsLog(
                            "            Did not find port *********** portid={0} proto={1}".format(
                                p.portId, p.protocol
                            )
                        )
                        if db_service:
                            db_port = portObj(p.portId, p.protocol, p.state, db_host.id, db_service.id)
                        else:
                            db_port = portObj(p.portId, p.protocol, p.state, db_host.id, '')
                        session.add(db_port)
                        session.commit()

                    # Update global progress for each port
                    total_ports_processed += 1
                    if total_ports > 0:
                        port_progress = int((total_ports_processed / total_ports) * 100)
                        if port_progress <= 100:
                            if self.updateProgressObservable is not None:
                                self.updateProgressObservable.updateProgress(
                                    port_progress, 'Processing ports...'
                                )
                            self.progressUpdated.emit(port_progress, 'Processing ports...')

                createPortsProgress = createPortsProgress + (100.0 / hostCount)
                now_ports = time()
                if (
                    self.updateProgressObservable is not None
                    and (now_ports - last_update_time_ports > update_interval_ports or createPortsProgress >= 100)
                ):
                    self.updateProgressObservable.updateProgress(
                        int(createPortsProgress), 'Processing ports...'
                    )
                    self.progressUpdated.emit(int(createPortsProgress), 'Processing ports...')
                    last_update_time_ports = now_ports

            # --- Begin global script progress calculation ---
            # Calculate total number of scripts (port scripts + host scripts) across all hosts
            total_scripts = 0
            for h in allHosts:
                for p in h.all_ports():
                    total_scripts += len(p.getScripts())
                total_scripts += len(h.getHostScripts())
            total_scripts_processed = 0
            # --- End global script progress calculation ---

            if self.updateProgressObservable is not None:
                self.updateProgressObservable.updateProgress(0, 'Creating script objects...')
            self.progressUpdated.emit(0, 'Creating script objects...')

            for h in allHosts:  # create all script objects that need to be created
                db_host = self.hostRepository.getHostInformation(h.ip)

                for p in h.all_ports():
                    for scr in p.getScripts():
                        if self._cancel_requested:
                            self.tsLog("Import canceled by user during script creation.")
                            if self.updateProgressObservable is not None:
                                self.updateProgressObservable.finished()
                            self.done.emit()
                            return
                        self.tsLog("        Processing script obj {scr}".format(scr=str(scr)))
                        db_port = session.query(portObj).filter_by(hostId=db_host.id) \
                            .filter_by(portId=p.portId).filter_by(protocol=p.protocol).first()
                        # Todo
                        db_script = session.query(l1ScriptObj).filter_by(scriptId=scr.scriptId) \
                            .filter_by(portId=db_port.id).first()
                        # end todo
                        db_script = session.query(l1ScriptObj).filter_by(hostId=db_host.id) \
                           .filter_by(portId=db_port.id).first()

                        if not db_script:  # if this script object doesn't exist, create it
                            t_l1ScriptObj = l1ScriptObj(scr.scriptId, scr.output, db_port.id, db_host.id)
                            self.tsLog("        Adding l1ScriptObj obj {script}".format(script=scr.scriptId))
                            session.add(t_l1ScriptObj)
                            session.commit()
                        # Update global script progress
                        total_scripts_processed += 1
                        if total_scripts > 0:
                            script_progress = int((total_scripts_processed / total_scripts) * 100)
                            if self.updateProgressObservable is not None:
                                self.updateProgressObservable.updateProgress(
                                    script_progress, 'Creating script objects...'
                                )
                            self.progressUpdated.emit(script_progress, 'Creating script objects...')
                for hs in h.getHostScripts():
                    if self._cancel_requested:
                        self.tsLog("Import canceled by user during script creation.")
                        if self.updateProgressObservable is not None:
                            self.updateProgressObservable.finished()
                        self.done.emit()
                        return
                    db_script = session.query(l1ScriptObj).filter_by(scriptId=hs.scriptId) \
                        .filter_by(hostId=db_host.id).first()
                    if not db_script:
                        t_l1ScriptObj = l1ScriptObj(hs.scriptId, hs.output, None, db_host.id)
                        session.add(t_l1ScriptObj)
                        session.commit()
                    # Update global script progress
                    total_scripts_processed += 1
                    if total_scripts > 0:
                        script_progress = int((total_scripts_processed / total_scripts) * 100)
                        if self.updateProgressObservable is not None:
                            self.updateProgressObservable.updateProgress(
                                script_progress, 'Creating script objects...'
                            )
                        self.progressUpdated.emit(script_progress, 'Creating script objects...')

            # --- Begin global update objects progress calculation ---
            total_update_hosts = len(allHosts)
            update_hosts_processed = 0
            update_progress = 0
            # --- End global update objects progress calculation ---

            if self.updateProgressObservable is not None:
                self.updateProgressObservable.updateProgress(0, 'Update objects and run scripts...')
            self.progressUpdated.emit(0, 'Update objects and run scripts...')

            for h in allHosts:  # update everything

                db_host = self.hostRepository.getHostInformation(h.ip)
                if not db_host:
                    self.tsLog(
                        "A host that should have been found was not. Something is wrong. "
                        "Save your session and report a bug."
                    )
                    self.tsLog("Include your nmap file, sanitized if needed.")

                # Check if any vulners script is present for this host or its ports
                has_vulners = False
                for scr in h.getHostScripts():
                    if 'vulners' in str(scr.scriptId).lower():
                        has_vulners = True
                        break
                if not has_vulners:
                    for p in h.all_ports():
                        for scr in p.getScripts():
                            if 'vulners' in str(scr.scriptId).lower():
                                has_vulners = True
                                break
                        if has_vulners:
                            break

                # Only update/replace CVEs if vulners data is present
                if has_vulners:
                    # Remove existing CVEs for this host
                    session.execute(
                        "DELETE FROM cve WHERE hostId = :hostId",
                        {'hostId': db_host.id}
                    )
                    session.commit()
                    # Add new CVEs from vulners scripts
                    for scr in h.getHostScripts():
                        for cve_obj in scr.scriptSelector(db_host):
                            session.add(cve_obj)
                            session.commit()
                    for p in h.all_ports():
                        db_port = session.query(portObj).filter_by(hostId=db_host.id).filter_by(portId=p.portId) \
                            .filter_by(protocol=p.protocol).first()
                        for scr in p.getScripts():
                            for cve_obj in scr.scriptSelector(db_host):
                                session.add(cve_obj)
                                session.commit()
                # If no vulners data, do not touch existing CVEs

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
                session.commit()

                tmp_name = ''
                tmp_accuracy = '0'  # TODO: check if better to convert to int for comparison

                os_nodes = h.getOs()
                for os in os_nodes:
                    db_os = session.query(osObj).filter_by(hostId=db_host.id).filter_by(name=os.name) \
                        .filter_by(family=os.family).filter_by(generation=os.generation) \
                        .filter_by(osType=os.osType).filter_by(vendor=os.vendor).first()

                    db_os.osAccuracy = os.accuracy  # update the accuracy

                    # get the most accurate OS match/accuracy to store it in the host table for easier access
                    if not os.name == '':
                        if os.accuracy > tmp_accuracy:
                            tmp_name = os.name
                            tmp_accuracy = os.accuracy

                if os_nodes:  # if there was operating system info to parse
                    # update the current host with the most accurate OS match
                    if not tmp_name == '' and not tmp_accuracy == '0':
                        db_host.osMatch = tmp_name
                        db_host.osAccuracy = tmp_accuracy

                session.add(db_host)
                session.commit()

                for scr in h.getHostScripts():
                    self.tsLog("-----------------------Host SCR: {0}".format(scr.scriptId))
                    db_host = self.hostRepository.getHostInformation(h.ip)
                    scrProcessorResults = scr.scriptSelector(db_host)
                    for scrProcessorResult in scrProcessorResults:
                        session.add(scrProcessorResult)
                        session.commit()

                for scr in h.getScripts():
                    self.tsLog("-----------------------SCR: {0}".format(scr.scriptId))
                    db_host = self.hostRepository.getHostInformation(h.ip)
                    scrProcessorResults = scr.scriptSelector(db_host)
                    for scrProcessorResult in scrProcessorResults:
                        session.add(scrProcessorResult)
                        session.commit()

                for p in h.all_ports():
                    s = p.getService()
                    if not (s is None):
                        db_service = session.query(serviceObj).filter_by(hostId=db_host.id) \
                            .filter_by(name=s.name).filter_by(product=s.product) \
                            .filter_by(version=s.version).filter_by(extrainfo=s.extrainfo) \
                            .filter_by(fingerprint=s.fingerprint).first()
                    else:
                        db_service = None
                        # fetch the port
                    db_port = session.query(portObj).filter_by(hostId=db_host.id).filter_by(portId=p.portId) \
                        .filter_by(protocol=p.protocol).first()
                    if db_port:
                        if db_port.state != p.state:
                            db_port.state = p.state
                            session.add(db_port)
                            session.commit()
                        # if there is some new service information, update it -- might be causing issue 164
                        if not (db_service is None) and db_port.serviceId != db_service.id:
                            db_port.serviceId = db_service.id
                            session.add(db_port)
                            session.commit()
                    # store the script results (note that existing script outputs are also kept)
                    for scr in p.getScripts():
                        db_script = session.query(l1ScriptObj).filter_by(scriptId=scr.scriptId) \
                            .filter_by(portId=db_port.id).first()

                        if db_script:
                            if not scr.output == '' and scr.output != None:
                                db_script.output = scr.output

                            session.add(db_script)
                        session.commit()

                # Update global update objects progress
                update_hosts_processed += 1
                if total_update_hosts > 0:
                    update_progress = int((update_hosts_processed / total_update_hosts) * 100)
                    if update_progress <= 100:
                        if self.updateProgressObservable is not None:
                            self.updateProgressObservable.updateProgress(
                                update_progress, 'Update objects and run scripts...'
                            )
                        self.progressUpdated.emit(update_progress, 'Update objects and run scripts...')

            final_progress = 100 if total_update_hosts == 0 else update_progress
            if self.updateProgressObservable is not None:
                self.updateProgressObservable.updateProgress(100, 'Almost done...')
            self.progressUpdated.emit(final_progress, 'Almost done...')

            session.commit()
            self.db.dbsemaphore.release()  # we are done with the DB
            self.tsLog(f"Finished in {str(time() - startTime)} seconds.")
            if self.updateProgressObservable is not None:
                self.updateProgressObservable.finished()
            appLog.debug("NmapImporter: emitting done signal")
            self.done.emit()

            # Removed periodic progress updates (QTimer) due to threading issues.

            # call the scheduler (if there is no terminal output it means we imported nmap)
            self.schedule.emit(nmapReport, self.output == '')

        except Exception as e:
            self.tsLog('Something went wrong when parsing the nmap file..')
            self.tsLog("Unexpected error: {0}".format(sys.exc_info()[0]))
            self.tsLog(e)
            if self.updateProgressObservable is not None:
                self.updateProgressObservable.finished()
            self.done.emit()
            self.stopProgressTimer()
            raise
