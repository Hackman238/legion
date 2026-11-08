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
import ipaddress
import re
import sys

try:
    from PyQt6 import QtCore
except Exception:  # pragma: no cover - exercised only in non-Qt environments.
    class _Signal:
        def __init__(self):
            self._callbacks = []

        def connect(self, callback):
            if callable(callback):
                self._callbacks.append(callback)

        def emit(self, *args, **kwargs):
            for callback in list(self._callbacks):
                try:
                    callback(*args, **kwargs)
                except Exception:
                    pass

    class _SignalDescriptor:
        def __set_name__(self, owner, name):
            self._name = f"__signal_{name}"

        def __get__(self, instance, owner):
            if instance is None:
                return self
            signal = instance.__dict__.get(self._name)
            if signal is None:
                signal = _Signal()
                instance.__dict__[self._name] = signal
            return signal

    class _FallbackQThread:
        def __init__(self, parent=None):
            self._parent = parent

        def start(self):
            self.run()

    class _FallbackQtCore:
        QThread = _FallbackQThread

        @staticmethod
        def pyqtSignal(*_args, **_kwargs):
            return _SignalDescriptor()

    QtCore = _FallbackQtCore()
from sqlalchemy import func, or_, text

from app.actions.updateProgress import AbstractUpdateProgressObservable
from app.hostsfile import add_temporary_host_alias
from app.logging.legionLog import getAppLogger
from app.nmap_enrichment import (
    infer_hostname_from_nmap_data,
    infer_os_from_service_inventory,
    infer_os_from_nmap_scripts,
    is_unknown_hostname,
    is_unknown_os_match,
)
from db.entities.cve import cve
from db.entities.host import hostObj
from db.entities.l1script import l1ScriptObj
from db.entities.nmapSession import nmapSessionObj
from db.entities.note import note
from db.entities.os import osObj
from db.entities.port import portObj
from db.entities.service import serviceObj
from db.repositories.HostRepository import HostRepository
from parsers.Parser import parseNmapReport, MalformedXmlDocumentException
from parsers.Script import Script
from time import time

appLog = getAppLogger()

def _new_import_session(database):
    new_session = getattr(database, "new_session", None)
    return new_session() if callable(new_session) else database.session()


class NmapImporter(QtCore.QThread):
    tick = QtCore.pyqtSignal(int, name="changed")  # New style signal
    done = QtCore.pyqtSignal(name="done")  # New style signal
    schedule = QtCore.pyqtSignal(object, bool, name="schedule")  # New style signal
    log = QtCore.pyqtSignal(str, name="log")
    HOST_COMMIT_BATCH = 50  # new hosts per commit while adding hosts
    progressUpdated = QtCore.pyqtSignal(int, str)  # progress, title
    failed = QtCore.pyqtSignal(str)  # error message when an import fails (run() never raises)

    def __init__(self, updateProgressObservable: AbstractUpdateProgressObservable, hostRepository: HostRepository):
        QtCore.QThread.__init__(self, parent=None)
        self.output = ''
        self.updateProgressObservable = updateProgressObservable
        self.hostRepository = hostRepository
        self._cancel_requested = False  # Cancellation flag

    def cancel(self):
        self._cancel_requested = True

    def resetCancel(self):
        """Clear a cancel request; call when starting a new import (not inside the run, so an early cancel
        pressed right after start() is still honoured)."""
        self._cancel_requested = False

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
                    self._getProcessRepository().storeProcessPercent(self.processId, str(highest_percent))
                else:
                    self.tsLog("[Periodic] No percent found in XML.")
                    appLog.debug("[Periodic] No percent found in XML.")
        except Exception as e:
            self.tsLog(f"Periodic percent update failed: {e}")
            appLog.debug(f"Periodic percent update failed: {e}")

    def tsLog(self, msg):
        self.log.emit(str(msg))

    def _getProcessRepository(self):
        # self.db is a Database adapter (it has no repositoryContainer); build a ProcessRepository on top of it.
        db = getattr(self, "_run_db", None) or self.db
        repo = getattr(self, "processRepository", None)
        if repo is None or getattr(repo, "dbAdapter", None) is not db:
            from app.logging.legionLog import getDbLogger
            from db.repositories.ProcessRepository import ProcessRepository
            repo = ProcessRepository(db, getDbLogger())
            self.processRepository = repo
        return repo

    @staticmethod
    def _storedVulnersState(session, db_host, h):
        """What the host's already-stored vulners script rows say.

        Returns (pairs_outside_scan, products): the (product, version) pairs reported for ports this scan does
        not cover (their CVEs must survive a partial re-scan), and every product any stored vulners output
        mentions, including ports this scan covers again (their stored output is the previous scan's).
        """
        scanned = {(str(p.portId), str(p.protocol)) for p in h.all_ports()}
        scanned_port_ids = {
            str(row.id)
            for row in session.query(portObj).filter_by(hostId=db_host.id).all()
            if (str(row.portId), str(row.protocol)) in scanned
        }
        scan_has_host_vulners = any('vulners' in str(scr.scriptId).lower() for scr in h.getHostScripts())
        pairs_outside_scan, products = set(), set()
        for row in session.query(l1ScriptObj).filter_by(hostId=db_host.id).all():
            if 'vulners' not in str(row.scriptId or '').lower():
                continue
            pairs = Script.vulnersProductVersions(row.output)
            products |= {product for product, _version in pairs}
            if row.portId in (None, ''):
                covered_by_scan = scan_has_host_vulners
            else:
                covered_by_scan = str(row.portId) in scanned_port_ids
            if not covered_by_scan:
                pairs_outside_scan |= pairs
        return pairs_outside_scan, products

    def _replaceVulnersCves(self, session, db_host, h, new_cves):
        """Store this scan's vulners CVEs, superseding only the stored rows they make stale.

        CVE rows are not linked to ports, so which rows to drop is decided from (product, version):
        - rows for a (product, version) this scan reports are replaced by this scan's rows;
        - rows for a product vulners reported (now or in a stored scan) whose version no port of the host
          runs any more are dropped (e.g. after an upgrade, or a service replaced on a re-scanned port);
        - everything else stays: versions still present on ports outside this scan, products vulners never
          reported, and version-less rows (manually added CVEs).
        """
        scanned_pairs = {(str(c.product or "").lower(), str(c.version or "")) for c in new_cves}
        pairs_outside_scan, known_products = self._storedVulnersState(session, db_host, h)
        expected_pairs = scanned_pairs | pairs_outside_scan
        known_products |= {product for product, _version in scanned_pairs}
        for row in session.query(cve).filter(cve.hostId == str(db_host.id)).all():
            product = str(row.product or "").lower()
            version = str(row.version or "")
            if product not in known_products:
                continue
            if (product, version) in scanned_pairs:
                session.delete(row)
            elif version and (product, version) not in expected_pairs:
                session.delete(row)
        session.add_all(new_cves)

    @staticmethod
    def _getDbHost(session, ip):
        # Query through the importer's own session so lookups see rows flushed earlier in this import.
        return session.query(hostObj).filter_by(ip=str(ip)).first()

    @staticmethod
    def _isIpAddress(value):
        try:
            ipaddress.ip_address(str(value or "").strip())
        except ValueError:
            return False
        return True

    def _adoptHostnamePlaceholder(self, session, h):
        """Return the row a hostname target was imported as (ip == hostname, see app.cli_utils.import_targets)
        once nmap has resolved that hostname to h.ip, after pointing the row at the real address; None otherwise.
        Without this the resolved host would be stored a second time and the placeholder never updated."""
        hostname = str(getattr(h, "hostname", "") or "").strip()
        if not hostname or is_unknown_hostname(hostname) or self._isIpAddress(hostname):
            return None
        lowered = hostname.lower()
        candidates = session.query(hostObj).filter(
            or_(func.lower(hostObj.ip) == lowered, func.lower(hostObj.hostname) == lowered)
        ).order_by(hostObj.id).all()
        for row in candidates:
            if self._isIpAddress(row.ip):
                continue  # a real address that merely shares the hostname is a different host
            row.ip = h.ip
            if not self._isEmptyHostValue(h.ipv4):
                row.ipv4 = h.ipv4
            elif not self._isIpAddress(row.ipv4):
                row.ipv4 = ''  # the placeholder's hostname text; the scan reported no IPv4 address
            if not self._isEmptyHostValue(h.ipv6):
                row.ipv6 = h.ipv6
            session.add(row)
            session.flush()
            self.tsLog(f"Resolved imported target {hostname} to {h.ip}")
            return row
        return None

    @staticmethod
    def _isEmptyHostValue(value):
        # hostObj stores missing values as 'unknown' and a missing OS accuracy as 'NaN'.
        if value is None:
            return True
        text_value = str(value).strip()
        return text_value == '' or text_value.lower() in ('unknown', 'nan')

    @staticmethod
    def _isPlaceholderHostname(db_host):
        """True when the stored hostname carries no name: unknown, or the host's own address (targets imported
        from a list are stored with their IP as hostname, see app.cli_utils.import_targets)."""
        hostname = str(getattr(db_host, "hostname", "") or "").strip()
        if is_unknown_hostname(hostname):
            return True
        addresses = {str(getattr(db_host, field, "") or "").strip().lower() for field in ("ip", "ipv4", "ipv6")}
        return hostname.lower() in addresses

    def _fillHostField(self, db_host, field, new_value):
        # hostObj stores missing values as 'unknown', so treat '', 'unknown' and None as empty.
        if self._isEmptyHostValue(getattr(db_host, field, None)) and not self._isEmptyHostValue(new_value):
            setattr(db_host, field, new_value)

    def _abortForCancel(self, session, message):
        self.tsLog(message)
        # Keep whatever has been imported so far (previously every row was committed immediately).
        try:
            session.commit()
        except Exception:
            session.rollback()
        if self.updateProgressObservable is not None:
            self.updateProgressObservable.finished()
        self.done.emit()

    def setDB(self, db):
        self.db = db

    def setHostRepository(self, hostRepository: HostRepository):
        self.hostRepository = hostRepository

    def setFilename(self, filename):
        self.filename = filename

    def setOutput(self, output):
        self.output = output

    def run(self):
        """QThread entry point. Never lets an exception escape: under PyQt6 an exception leaving a QThread's
        run() aborts the whole application (SIGABRT), so a failed import is reported via `failed` instead."""
        try:
            self.importFile()
        except Exception as exc:
            appLog.exception("Nmap XML import failed: %s", getattr(self, "filename", ""))
            try:
                self.failed.emit(f"Nmap import failed for {getattr(self, 'filename', '')}: {exc}")
            except Exception:
                pass

    # it is necessary to get the qprocess because we need to send it back to the scheduler when we're done importing
    def importFile(self):
        """Import self.filename synchronously; raises on failure (used directly by headless/web callers)."""
        session = None
        db_lock_acquired = False
        # Pin the file for this run: setFilename() for a queued import must not change it mid-import.
        import_filename = self.filename
        # Pin the database for this run: setDB() may be called mid-import (e.g. after Save As), and the
        # session and write semaphore must stay on the database the import started with.
        run_db = self.db
        self._run_db = run_db
        try:
            # Removed periodic progress updates (QTimer) due to threading issues.
            if self.updateProgressObservable is not None:
                self.updateProgressObservable.start()
            # An independent session: repository calls on this thread close the thread-scoped session,
            # which would otherwise discard this import's flushed-but-uncommitted rows.
            session = _new_import_session(run_db)
            self.tsLog("Parsing nmap xml file: " + import_filename)
            startTime = time()

            import os
            nmap_xml_path = import_filename
            if not os.path.isfile(nmap_xml_path):
                parent_dir = os.path.dirname(nmap_xml_path)
                base_name = os.path.basename(nmap_xml_path)
                found_path = ""
                if os.path.isdir(parent_dir):
                    for sub in os.listdir(parent_dir):
                        sub_path = os.path.join(parent_dir, sub, base_name)
                        if os.path.isfile(sub_path):
                            found_path = sub_path
                            break
                if found_path:
                    self.tsLog(f"Found nmap xml in subdirectory: {found_path}")
                    nmap_xml_path = found_path
                else:
                    self.tsLog('Giving up on import due to previous errors.')
                    appLog.error("Nmap XML import failed: report not found: %s", nmap_xml_path)
                    # Raise so callers (web/MCP jobs, run() -> `failed`) see the failure; the handler below
                    # still reports finished/done to the UI.
                    raise FileNotFoundError(f"Nmap XML report not found: {nmap_xml_path}")

            try:
                nmapReport = parseNmapReport(nmap_xml_path)
            except (MalformedXmlDocumentException, FileNotFoundError) as e:
                self.tsLog('Giving up on import due to previous errors.')
                appLog.error(f"Nmap XML import failed: the report is likely malformed: {e}")
                raise MalformedXmlDocumentException(
                    f"Nmap XML report is malformed or unreadable: {nmap_xml_path}: {e}"
                ) from e

            self.tsLog('nmap xml report read successfully!')
            run_db.dbsemaphore.acquire()  # ensure that while this thread is running, no one else can write to the DB
            db_lock_acquired = True
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
                        # Through this import's own session: a second connection would wait on our write lock.
                        session.execute(
                            text("UPDATE process SET percent = :percent WHERE id = :id"),
                            {"percent": str(highest_percent), "id": int(self.processId)},
                        )
                        # Commit on its own: a duplicate nmap-session insert below rolls back its transaction.
                        session.commit()
                except Exception as e:
                    self.tsLog(f"Failed to set highest percent: {e}")
                n = nmapSessionObj(
                    import_filename, s.startTime, s.finish_time, s.nmapVersion, s.scanArgs, s.totalHosts,
                    s.upHosts, s.downHosts
                )
                try:
                    session.add(n)
                    session.commit()
                except Exception as e:
                    from sqlalchemy.exc import IntegrityError
                    if isinstance(e, IntegrityError):
                        msg = (
                            f"Duplicate nmap session for filename '{import_filename}' detected. "
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
            pending_new_hosts = 0
            for h in allHosts:  # create all the hosts that need to be created
                if self._cancel_requested:
                    self._abortForCancel(session, "Import canceled by user.")
                    return

                db_host = self._getDbHost(session, h.ip)
                if not db_host:
                    db_host = self._adoptHostnamePlaceholder(session, h)

                if not db_host:  # if host doesn't exist in DB, create it first
                    hid = hostObj(
                        osMatch='', osAccuracy='', ip=h.ip, ipv4=h.ipv4, ipv6=h.ipv6, macaddr=h.macaddr,
                        status=h.status, hostname=h.hostname, vendor=h.vendor, uptime=h.uptime,
                        lastboot=h.lastboot, distance=h.distance, state=h.state, count=h.count
                    )
                    self.tsLog("Adding db_host")
                    session.add(hid)
                    session.flush()  # assign hid.id so the note references the host row, not its IP
                    t_note = note(hid.id, 'Added by nmap')
                    session.add(t_note)
                    session.flush()
                    pending_new_hosts += 1
                    if pending_new_hosts >= self.HOST_COMMIT_BATCH:
                        # Commit in batches so other writers are not blocked for the whole phase.
                        session.commit()
                        pending_new_hosts = 0
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

            session.commit()

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

                db_host = self._getDbHost(session, h.ip)
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
                        session.flush()

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
                        self._abortForCancel(session, "Import canceled by user during port processing.")
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
                            session.flush()
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
                        session.flush()

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

                # Commit once per host (not per row) so other writers are not locked out for a whole phase.
                session.commit()

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

            session.commit()

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
                if h is None:
                    self.tsLog("Encountered empty host entry while creating scripts; skipping.")
                    appLog.warning("Skipping script creation for a null host entry from nmap report.")
                    continue

                db_host = self._getDbHost(session, h.ip)
                if not db_host:
                    self.tsLog(
                        "A host that should have been found was not. Skipping script creation for this host."
                    )
                    appLog.warning("Skipping script creation for host %s because it is missing in the database.", h.ip)
                    continue

                for p in h.all_ports():
                    for scr in p.getScripts():
                        if self._cancel_requested:
                            self._abortForCancel(session, "Import canceled by user during script creation.")
                            return
                        self.tsLog("        Processing script obj {scr}".format(scr=str(scr)))
                        db_port = session.query(portObj).filter_by(hostId=db_host.id) \
                            .filter_by(portId=p.portId).filter_by(protocol=p.protocol).first()
                        if not db_port:
                            self.tsLog(
                                "Skipping script {script} for host {host} port {port}/{protocol}; port not in database.".format(
                                    script=scr.scriptId, host=h.ip, port=p.portId, protocol=p.protocol
                                )
                            )
                            appLog.warning(
                                "Skipping script %s for host %s port %s/%s because the port is missing in the database.",
                                scr.scriptId, h.ip, p.portId, p.protocol
                            )
                            continue
                        db_script = session.query(l1ScriptObj).filter_by(hostId=db_host.id) \
                            .filter_by(portId=db_port.id).filter_by(scriptId=scr.scriptId).first()

                        if not db_script:  # if this script object doesn't exist, create it
                            t_l1ScriptObj = l1ScriptObj(scr.scriptId, scr.output, db_port.id, db_host.id)
                            self.tsLog("        Adding l1ScriptObj obj {script}".format(script=scr.scriptId))
                            session.add(t_l1ScriptObj)
                            session.flush()
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
                        self._abortForCancel(session, "Import canceled by user during script creation.")
                        return
                    db_script = session.query(l1ScriptObj).filter_by(scriptId=hs.scriptId) \
                        .filter_by(hostId=db_host.id).first()
                    if not db_script:
                        t_l1ScriptObj = l1ScriptObj(hs.scriptId, hs.output, None, db_host.id)
                        session.add(t_l1ScriptObj)
                        session.flush()
                    # Update global script progress
                    total_scripts_processed += 1
                    if total_scripts > 0:
                        script_progress = int((total_scripts_processed / total_scripts) * 100)
                        if self.updateProgressObservable is not None:
                            self.updateProgressObservable.updateProgress(
                                script_progress, 'Creating script objects...'
                            )
                        self.progressUpdated.emit(script_progress, 'Creating script objects...')
                session.commit()  # once per host

            # --- Begin global update objects progress calculation ---
            total_update_hosts = len(allHosts)
            update_hosts_processed = 0
            update_progress = 0
            # --- End global update objects progress calculation ---

            if self.updateProgressObservable is not None:
                self.updateProgressObservable.updateProgress(0, 'Update objects and run scripts...')
            self.progressUpdated.emit(0, 'Update objects and run scripts...')

            for h in allHosts:  # update everything

                db_host = self._getDbHost(session, h.ip)
                if not db_host:
                    self.tsLog(
                        "A host that should have been found was not. Something is wrong. "
                        "Save your session and report a bug."
                    )
                    self.tsLog("Include your nmap file, sanitized if needed.")
                    appLog.warning(
                        "Host %s was expected in the database during update but could not be found; skipping.",
                        getattr(h, "ip", "<unknown>")
                    )
                    continue

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
                    # Build CVEs from vulners scripts (host scripts and port scripts) before writing anything:
                    # the exploit-db lookups are slow and must not run while this session holds the SQLite
                    # write lock. This is the only place script-derived CVEs are inserted; dedupe so a CVE
                    # reported twice is stored once.
                    seen_cves = set()
                    new_cves = []
                    vulners_scripts = list(h.getHostScripts())
                    for p in h.all_ports():
                        vulners_scripts.extend(p.getScripts())
                    for scr in vulners_scripts:
                        if 'vulners' not in str(scr.scriptId).lower():
                            continue
                        for cve_obj in scr.scriptSelector(db_host):
                            cve_key = (cve_obj.name, cve_obj.product, cve_obj.version)
                            if cve_key in seen_cves:
                                continue
                            seen_cves.add(cve_key)
                            new_cves.append(cve_obj)
                    self._replaceVulnersCves(session, db_host, h, new_cves)
                    session.flush()
                # If no vulners data, do not touch existing CVEs

                self._fillHostField(db_host, 'ipv4', h.ipv4)
                self._fillHostField(db_host, 'ipv6', h.ipv6)
                self._fillHostField(db_host, 'macaddr', h.macaddr)
                if not h.status == '':
                    db_host.status = h.status
                script_records = self._collect_script_records(h)
                inferred_hostname = infer_hostname_from_nmap_data(getattr(h, "hostname", ""), script_records)
                if self._isPlaceholderHostname(db_host) and inferred_hostname:
                    db_host.hostname = inferred_hostname
                    self.tsLog(f"Inferred hostname for {db_host.ip}: {inferred_hostname}")
                    added, reason = add_temporary_host_alias(db_host.ip, inferred_hostname)
                    if not added:
                        self.tsLog(f"Skipped /etc/hosts update for {db_host.ip} ({inferred_hostname}): {reason}")
                self._fillHostField(db_host, 'vendor', h.vendor)
                self._fillHostField(db_host, 'uptime', h.uptime)
                self._fillHostField(db_host, 'lastboot', h.lastboot)
                # the parser defaults distance to 0 when nmap reported none
                self._fillHostField(db_host, 'distance', h.distance or '')
                self._fillHostField(db_host, 'state', h.state)
                self._fillHostField(db_host, 'count', h.count)

                session.add(db_host)

                tmp_name = ''
                tmp_accuracy = '0'
                best_accuracy = 0

                os_nodes = h.getOs()
                for os in os_nodes:
                    db_os = session.query(osObj).filter_by(hostId=db_host.id).filter_by(name=os.name) \
                        .filter_by(family=os.family).filter_by(generation=os.generation) \
                        .filter_by(osType=os.osType).filter_by(vendor=os.vendor).first()

                    if db_os is not None:
                        db_os.accuracy = os.accuracy  # update the accuracy

                    # get the most accurate OS match/accuracy to store it in the host table for easier access
                    if not os.name == '':
                        # nmap reports accuracy as a string such as "98" or "98%"; compare
                        # numerically so "100" beats "95"
                        accuracy_match = re.match(r"\s*(\d+)", str(os.accuracy or ""))
                        accuracy_value = int(accuracy_match.group(1)) if accuracy_match else 0
                        if accuracy_value > best_accuracy:
                            best_accuracy = accuracy_value
                            tmp_name = os.name
                            tmp_accuracy = os.accuracy

                if os_nodes:  # if there was operating system info to parse
                    # update the current host with the most accurate OS match
                    if not tmp_name == '' and not tmp_accuracy == '0':
                        db_host.osMatch = tmp_name
                        db_host.osAccuracy = tmp_accuracy

                if is_unknown_os_match(getattr(db_host, "osMatch", "")):
                    inferred_os = infer_os_from_nmap_scripts(script_records)
                    if not inferred_os:
                        service_records = self._collect_service_records(h)
                        inferred_os = infer_os_from_service_inventory(service_records)
                    if inferred_os:
                        db_host.osMatch = inferred_os
                        if self._isEmptyHostValue(getattr(db_host, "osAccuracy", "")):
                            db_host.osAccuracy = "85"
                        self.tsLog(f"Inferred OS for {db_host.ip} from scripts: {inferred_os}")

                session.add(db_host)
                session.flush()

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
                    if not db_port:
                        self.tsLog(
                            "Skipping updates for host {host} port {port}/{protocol}; port not found in database.".format(
                                host=db_host.ip, port=p.portId, protocol=p.protocol
                            )
                        )
                        appLog.warning(
                            "Skipping updates for host %s port %s/%s because the port is missing in the database.",
                            db_host.ip, p.portId, p.protocol
                        )
                        continue
                    if db_port.state != p.state:
                        db_port.state = p.state
                        session.add(db_port)
                    # if there is some new service information, update it -- might be causing issue 164
                    if not (db_service is None) and str(db_port.serviceId) != str(db_service.id):
                        db_port.serviceId = db_service.id
                        session.add(db_port)
                    # store the script results (note that existing script outputs are also kept)
                    for scr in p.getScripts():
                        db_script = session.query(l1ScriptObj).filter_by(scriptId=scr.scriptId) \
                            .filter_by(portId=db_port.id).first()

                        if db_script:
                            if not scr.output == '' and scr.output != None:
                                db_script.output = scr.output

                            session.add(db_script)
                session.commit()  # once per host

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
            # Release the DB write lock as soon as DB operations are done; follow-up UI/scheduler work
            # may also touch the DB.
            if db_lock_acquired:
                run_db.dbsemaphore.release()
                db_lock_acquired = False
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
            # Rows are flushed and committed in batches; keep what was already imported (as the former
            # per-row commits did) instead of letting session.close() roll it back.
            if session is not None:
                try:
                    session.commit()
                except Exception:
                    try:
                        session.rollback()
                    except Exception:
                        pass
            if self.updateProgressObservable is not None:
                self.updateProgressObservable.finished()
            # No `done` here: `done` means "hosts were imported" to the UI (overlay hidden, tables and
            # scheduler refreshed). run() reports the failure through `failed` instead.
            raise
        finally:
            # Always release the DB write lock (if acquired) and close the session to avoid leaked SQLite fds.
            try:
                if db_lock_acquired:
                    run_db.dbsemaphore.release()
            except Exception:
                pass
            self._run_db = None  # later calls follow setDB() again
            try:
                if session is not None:
                    session.close()
            except Exception:
                pass

    @staticmethod
    def _collect_script_records(host_report):
        records = []

        def _append_script(script_obj):
            if script_obj is None:
                return
            script_id = str(getattr(script_obj, "scriptId", "") or "")
            output = str(getattr(script_obj, "output", "") or "")
            if script_id and output:
                records.append((script_id, output))

        for script_obj in (host_report.getHostScripts() or []):
            _append_script(script_obj)
        for script_obj in (host_report.getScripts() or []):
            _append_script(script_obj)
        for port_obj in (host_report.all_ports() or []):
            for script_obj in (port_obj.getScripts() or []):
                _append_script(script_obj)

        return records

    @staticmethod
    def _collect_service_records(host_report):
        records = []
        for port_obj in (host_report.all_ports() or []):
            service_obj = port_obj.getService()
            if service_obj is None:
                continue
            records.append((
                str(getattr(service_obj, "name", "") or ""),
                str(getattr(service_obj, "product", "") or ""),
                str(getattr(service_obj, "version", "") or ""),
                str(getattr(service_obj, "extrainfo", "") or ""),
            ))
        return records
