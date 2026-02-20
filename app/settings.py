#!/usr/bin/env python

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

"""

import shutil
import os
import re

from app.auxiliary import *  # for timestamp
from app.paths import (
    ensure_legion_home,
    get_legion_backup_dir,
    get_legion_conf_path,
)


# this class reads and writes application settings
from app.timing import getTimestamp

log = getAppLogger()

class AppSettings():
    WEB_SERVICE_SCOPE = "http,https,ssl,soap,http-proxy,http-alt,https-alt"
    REMOTE_SCREEN_SERVICE_SCOPE = "ms-wbt-server,rdp,vmrdp,vnc,vnc-http,rfb"
    SCREENSHOT_SERVICE_SCOPE = f"{WEB_SERVICE_SCOPE},{REMOTE_SCREEN_SERVICE_SCOPE}"
    WEB_CONTENT_GOBUSTER_COMMAND = (
        "(command -v gobuster >/dev/null 2>&1 && "
        "((gobuster -m dir -k -q -u https://[IP]:[PORT]/ -w /usr/share/wordlists/dirb/common.txt -o [OUTPUT].txt || "
        "gobuster -m dir -q -u http://[IP]:[PORT]/ -w /usr/share/wordlists/dirb/common.txt -o [OUTPUT].txt) || "
        "(gobuster dir -k -q -u https://[IP]:[PORT]/ -w /usr/share/wordlists/dirb/common.txt -o [OUTPUT].txt || "
        "gobuster dir -q -u http://[IP]:[PORT]/ -w /usr/share/wordlists/dirb/common.txt -o [OUTPUT].txt)))"
    )
    LEGACY_WEB_CONTENT_DISCOVERY_COMMAND = (
        "(command -v feroxbuster >/dev/null 2>&1 && "
        "(feroxbuster -u https://[IP]:[PORT] -k --silent -o [OUTPUT].txt || "
        "feroxbuster -u http://[IP]:[PORT] --silent -o [OUTPUT].txt)) || "
        "(command -v gobuster >/dev/null 2>&1 && "
        "gobuster dir -u http://[IP]:[PORT]/ -w /usr/share/wordlists/dirb/common.txt -o [OUTPUT].txt) || "
        "echo feroxbuster/gobuster not found"
    )
    WEB_CONTENT_DISCOVERY_COMMAND = (
        "(command -v feroxbuster >/dev/null 2>&1 && "
        "(feroxbuster -u https://[IP]:[PORT] -k --silent -o [OUTPUT].txt || "
        "feroxbuster -u http://[IP]:[PORT] --silent -o [OUTPUT].txt)) || "
        f"{WEB_CONTENT_GOBUSTER_COMMAND} || "
        "echo feroxbuster/gobuster not found"
    )
    NMAP_VULN_COMMAND = (
        "(nmap -Pn -n -sV -p [PORT] --script=vuln,vulners --stats-every 15s [IP] || "
        "nmap -Pn -n -sV -p [PORT] --script=vuln --stats-every 15s [IP])"
    )
    NUCLEI_WEB_COMMAND = (
        "(command -v nuclei >/dev/null 2>&1 && "
        "(nuclei -as -u https://[IP]:[PORT] -ni -silent -no-color -o [OUTPUT].txt || "
        "nuclei -as -u http://[IP]:[PORT] -ni -silent -no-color -o [OUTPUT].txt)) || "
        "echo nuclei not found"
    )
    NIKTO_COMMAND = "nikto -o [OUTPUT].txt -p [PORT] -h [IP] -C all"
    WAFW00F_COMMAND = (
        "(command -v wafw00f >/dev/null 2>&1 && "
        "(wafw00f https://[IP]:[PORT] || wafw00f http://[IP]:[PORT])) || "
        "echo wafw00f not found"
    )
    SSLSCAN_COMMAND = "sslscan --no-failed [IP]:[PORT]"
    SSLYZE_COMMAND = "sslyze --regular [IP]:[PORT]"
    WPSCAN_COMMAND = (
        "(command -v wpscan >/dev/null 2>&1 && "
        "(wpscan --url https://[IP]:[PORT] --disable-tls-checks || "
        "wpscan --url http://[IP]:[PORT])) || "
        "echo wpscan not found"
    )
    WAPITI_HTTP_COMMAND = (
        "(command -v wapiti >/dev/null 2>&1 && "
        "wapiti -u http://[IP]:[PORT] -n 10 -b folder -v 1 -f txt -o [OUTPUT]) || "
        "echo wapiti not found"
    )
    WAPITI_HTTPS_COMMAND = (
        "(command -v wapiti >/dev/null 2>&1 && "
        "wapiti -u https://[IP]:[PORT] -n 10 -b folder -v 1 -f txt -o [OUTPUT]) || "
        "echo wapiti not found"
    )
    BASELINE_WEB_PORT_ACTIONS = {
        "nikto": ("Run nikto", NIKTO_COMMAND, WEB_SERVICE_SCOPE),
        "wafw00f": ("Run wafw00f", WAFW00F_COMMAND, "https,ssl,https-alt"),
        "sslscan": ("Run sslscan", SSLSCAN_COMMAND, "https,ssl,https-alt"),
        "sslyze": ("Run sslyze", SSLYZE_COMMAND, "https,ssl,ms-wbt-server,imap,pop3,smtp,https-alt"),
        "wpscan": ("Run wpscan", WPSCAN_COMMAND, "http,https,ssl,https-alt"),
        "http-wapiti": ("Run wapiti (http)", WAPITI_HTTP_COMMAND, "http"),
        "https-wapiti": ("Run wapiti (https)", WAPITI_HTTPS_COMMAND, "https"),
    }

    def __init__(self):
        config_dir = ensure_legion_home()
        config_path = get_legion_conf_path()
        if not os.path.exists(config_path):
            repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
            default_conf = os.path.join(repo_root, "legion.conf")
            if os.path.exists(default_conf):
                shutil.copy(default_conf, config_path)
            else:
                log.error(f"Default configuration file not found at {default_conf}.")
        log.info(f"Loading settings file: {config_path}")
        self.actions = QtCore.QSettings(config_path, QtCore.QSettings.Format.NativeFormat)
        self._apply_default_action_migrations()

    def _apply_default_action_migrations(self):
        changed = False
        changed = self._migrate_port_actions() or changed
        changed = self._migrate_scheduler_settings() or changed
        if changed:
            self.actions.sync()
            log.info("Applied legion.conf action migration updates (nuclei/vuln/web-content-discovery).")

    def _migrate_port_actions(self):
        changed = False
        self.actions.beginGroup('PortActions')
        try:
            # Remove legacy GUI-only dirbuster action in favor of headless-safe web discovery.
            if self.actions.value('dirbuster') is not None:
                self.actions.remove('dirbuster')
                changed = True

            if self.actions.value('web-content-discovery') is None:
                self.actions.setValue('web-content-discovery', [
                    'Run web content discovery (feroxbuster/gobuster)',
                    self.WEB_CONTENT_DISCOVERY_COMMAND,
                    self.WEB_SERVICE_SCOPE,
                ])
                changed = True
            else:
                value = self.actions.value('web-content-discovery')
                label = 'Run web content discovery (feroxbuster/gobuster)'
                command = self.WEB_CONTENT_DISCOVERY_COMMAND
                scope = self.WEB_SERVICE_SCOPE

                if isinstance(value, (list, tuple)):
                    if len(value) > 0 and value[0]:
                        label = str(value[0])
                    if len(value) > 1 and value[1]:
                        command = str(value[1])
                    if len(value) > 2 and value[2]:
                        scope = str(value[2])

                updated_command = self._ensure_web_content_discovery_command(command)
                if updated_command != command:
                    self.actions.setValue('web-content-discovery', [label, updated_command, scope])
                    changed = True

            if self.actions.value('nmap-vuln.nse') is None:
                self.actions.setValue('nmap-vuln.nse', [
                    'nmap-vuln.nse',
                    self.NMAP_VULN_COMMAND,
                    self.WEB_SERVICE_SCOPE,
                ])
                changed = True
            else:
                value = self.actions.value('nmap-vuln.nse')
                label = 'nmap-vuln.nse'
                command = self.NMAP_VULN_COMMAND
                scope = self.WEB_SERVICE_SCOPE

                if isinstance(value, (list, tuple)):
                    if len(value) > 0 and value[0]:
                        label = str(value[0])
                    if len(value) > 1 and value[1]:
                        command = str(value[1])
                    if len(value) > 2 and value[2]:
                        scope = str(value[2])

                updated_command = self._ensure_nmap_vuln_command(command)
                if updated_command != command:
                    self.actions.setValue('nmap-vuln.nse', [label, updated_command, scope])
                    changed = True

            if self.actions.value('nuclei-web') is None:
                self.actions.setValue('nuclei-web', [
                    'Run nuclei web scan',
                    self.NUCLEI_WEB_COMMAND,
                    self.WEB_SERVICE_SCOPE,
                ])
                changed = True
            else:
                value = self.actions.value('nuclei-web')
                label = 'Run nuclei web scan'
                command = self.NUCLEI_WEB_COMMAND
                scope = self.WEB_SERVICE_SCOPE

                if isinstance(value, (list, tuple)):
                    if len(value) > 0 and value[0]:
                        label = str(value[0])
                    if len(value) > 1 and value[1]:
                        command = str(value[1])
                    if len(value) > 2 and value[2]:
                        scope = str(value[2])

                updated_command = self._ensure_nuclei_auto_scan(command)
                if updated_command != command:
                    self.actions.setValue('nuclei-web', [label, updated_command, scope])
                    changed = True

            for wapiti_key, expected_scheme, default_label, default_scope in (
                    ("http-wapiti", "http", "Run wapiti (http)", "http"),
                    ("https-wapiti", "https", "Run wapiti (https)", "https"),
            ):
                value = self.actions.value(wapiti_key)
                if value is None:
                    default_command = (
                        self.WAPITI_HTTPS_COMMAND
                        if expected_scheme == "https"
                        else self.WAPITI_HTTP_COMMAND
                    )
                    self.actions.setValue(wapiti_key, [default_label, default_command, default_scope])
                    changed = True
                    continue

                label = default_label
                command = (
                    self.WAPITI_HTTPS_COMMAND
                    if expected_scheme == "https"
                    else self.WAPITI_HTTP_COMMAND
                )
                scope = default_scope
                if isinstance(value, (list, tuple)):
                    if len(value) > 0 and value[0]:
                        label = str(value[0])
                    if len(value) > 1 and value[1]:
                        command = str(value[1])
                    if len(value) > 2 and value[2]:
                        scope = str(value[2])

                updated_command = self._ensure_wapiti_command(command, scheme=expected_scheme)
                if updated_command != command:
                    self.actions.setValue(wapiti_key, [label, updated_command, scope])
                    changed = True

            for key, value in self.BASELINE_WEB_PORT_ACTIONS.items():
                if self.actions.value(key) is None:
                    self.actions.setValue(key, [value[0], value[1], value[2]])
                    changed = True
        finally:
            self.actions.endGroup()
        return changed

    def _migrate_scheduler_settings(self):
        changed = False
        self.actions.beginGroup('SchedulerSettings')
        try:
            if self.actions.value('dirbuster') is not None:
                self.actions.remove('dirbuster')
                changed = True

            if self.actions.value('web-content-discovery') is None:
                self.actions.setValue('web-content-discovery', [self.WEB_SERVICE_SCOPE, 'tcp'])
                changed = True

            if self.actions.value('nmap-vuln.nse') is None:
                self.actions.setValue('nmap-vuln.nse', [self.WEB_SERVICE_SCOPE, 'tcp'])
                changed = True

            if self.actions.value('nuclei-web') is None:
                self.actions.setValue('nuclei-web', [self.WEB_SERVICE_SCOPE, 'tcp'])
                changed = True

            if self.actions.value('screenshooter') is None:
                self.actions.setValue('screenshooter', [self.SCREENSHOT_SERVICE_SCOPE, 'tcp'])
                changed = True
            else:
                value = self.actions.value('screenshooter')
                scope = self.SCREENSHOT_SERVICE_SCOPE
                protocol = "tcp"
                if isinstance(value, (list, tuple)):
                    if len(value) > 0 and value[0]:
                        scope = str(value[0])
                    if len(value) > 1 and value[1]:
                        protocol = str(value[1])

                updated_scope = self._ensure_scope_contains_services(
                    scope,
                    [item.strip() for item in self.SCREENSHOT_SERVICE_SCOPE.split(",") if item.strip()],
                )
                if updated_scope != scope:
                    self.actions.setValue('screenshooter', [updated_scope, protocol])
                    changed = True
        finally:
            self.actions.endGroup()
        return changed

    @staticmethod
    def _ensure_nuclei_auto_scan(command: str) -> str:
        raw = str(command or "")
        if "nuclei" not in raw.lower():
            return raw
        # Only patch direct scan invocations (`nuclei -u ...`), not probe checks
        # like `command -v nuclei` and not tokens embedded in output filenames.
        return re.sub(r"(?i)\bnuclei\b(?!\s+-as\b)(?=\s+-u\b)", "nuclei -as", raw)

    @staticmethod
    def _ensure_nmap_vuln_command(command: str) -> str:
        raw = str(command or "").strip()
        if "nmap" not in raw.lower() or "--script" not in raw.lower():
            return raw
        if "vuln" not in raw.lower():
            return raw

        if "||" in raw and "vulners" in raw.lower():
            return raw

        with_vulners = re.sub(
            r"(?i)--script(?:=|\s+)vuln\b",
            "--script=vuln,vulners",
            raw,
            count=1,
        )
        if with_vulners == raw and "vulners" not in raw.lower():
            return raw

        fallback = re.sub(
            r"(?i)--script(?:=|\s+)vuln(?:,vulners)?\b",
            "--script=vuln",
            with_vulners,
            count=1,
        )

        if with_vulners == fallback:
            return with_vulners
        return f"({with_vulners} || {fallback})"

    @staticmethod
    def _ensure_scope_contains_services(scope: str, required_services):
        existing = [item.strip() for item in str(scope or "").split(",") if item.strip()]
        lowered = {item.lower() for item in existing}
        changed = False
        for service in list(required_services or []):
            token = str(service or "").strip()
            if not token:
                continue
            if token.lower() not in lowered:
                existing.append(token)
                lowered.add(token.lower())
                changed = True
        if not existing:
            return ""
        return ",".join(existing) if changed else str(scope)

    @classmethod
    def _ensure_web_content_discovery_command(cls, command: str) -> str:
        raw = str(command or "")
        if "gobuster" not in raw.lower():
            return raw
        if cls.LEGACY_WEB_CONTENT_DISCOVERY_COMMAND == raw:
            return cls.WEB_CONTENT_DISCOVERY_COMMAND
        legacy_gobuster_block = (
            "(command -v gobuster >/dev/null 2>&1 && "
            "gobuster dir -u http://[IP]:[PORT]/ -w /usr/share/wordlists/dirb/common.txt -o [OUTPUT].txt)"
        )
        if legacy_gobuster_block in raw:
            return raw.replace(legacy_gobuster_block, cls.WEB_CONTENT_GOBUSTER_COMMAND)
        return raw

    @staticmethod
    def _ensure_wapiti_command(command: str, scheme: str = "http") -> str:
        raw = str(command or "")
        if "wapiti" not in raw.lower():
            return raw

        selected_scheme = "https" if str(scheme or "").strip().lower() == "https" else "http"
        url_target = f"{selected_scheme}://[IP]:[PORT]"

        # Keep tool-presence probe fragments untouched, for example:
        # `command -v wapiti >/dev/null 2>&1 && ...`
        probe_marker = "__LEGION_WAPITI_PROBE__"
        normalized = re.sub(
            r"(?i)command\s+-v\s+wapiti",
            f"command -v {probe_marker}",
            raw,
        )

        # Already valid command templates do not need further mutation.
        if re.search(r"(?i)\bwapiti\s+-u\s+https?://\[IP\](?::\[PORT\])?", normalized):
            return normalized.replace(probe_marker, "wapiti")

        # Remove positional URL argument after `wapiti` (legacy format).
        normalized = re.sub(
            r"(?i)\bwapiti\s+https?://\[IP\](?::\[PORT\])?",
            "wapiti",
            normalized,
            count=1,
        )
        # Remove explicit --url/-u usages so we can insert one canonical URL.
        normalized = re.sub(r"(?i)(?:--url|-u)\s+(?!-)\S+", "", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)(?:--url|-u)(?=\s|$)", " ", normalized)
        # Insert canonical URL argument.
        normalized = re.sub(r"(?i)\bwapiti\b", f"wapiti -u {url_target}", normalized, count=1)
        normalized = re.sub(r"\s{2,}", " ", normalized).strip()
        return normalized.replace(probe_marker, "wapiti")

    def getGeneralSettings(self):
        return self.getSettingsByGroup("GeneralSettings")

    def getBruteSettings(self):
        return self.getSettingsByGroup("BruteSettings")

    def getStagedNmapSettings(self):
        return self.getSettingsByGroup('StagedNmapSettings')

    def getToolSettings(self):
        return self.getSettingsByGroup('ToolSettings')

    def getGUISettings(self):
        return self.getSettingsByGroup('GUISettings')

    def getHostActions(self):
        self.actions.beginGroup('HostActions')
        hostactions = []
        sortArray = []
        keys = self.actions.childKeys()
        for k in keys:
            hostactions.append([self.actions.value(k)[0], str(k), self.actions.value(k)[1]])
            sortArray.append(self.actions.value(k)[0])
        self.actions.endGroup()
        sortArrayWithArray(sortArray, hostactions)  # sort by label so that it appears nicely in the context menu
        return hostactions

    # this function fetches all the host actions from the settings file
    def getPortActions(self):
        self.actions.beginGroup('PortActions')
        portactions = []
        sortArray = []
        keys = self.actions.childKeys()
        for k in keys:
            portactions.append([self.actions.value(k)[0], str(k), self.actions.value(k)[1], self.actions.value(k)[2]])
            sortArray.append(self.actions.value(k)[0])
        self.actions.endGroup()
        sortArrayWithArray(sortArray, portactions)  # sort by label so that it appears nicely in the context menu
        return portactions

    # this function fetches all the port actions from the settings file
    def getPortTerminalActions(self):
        self.actions.beginGroup('PortTerminalActions')
        portactions = []
        sortArray = []
        keys = self.actions.childKeys()
        for k in keys:
            portactions.append([self.actions.value(k)[0], str(k), self.actions.value(k)[1], self.actions.value(k)[2]])
            sortArray.append(self.actions.value(k)[0])
        self.actions.endGroup()
        sortArrayWithArray(sortArray, portactions)  # sort by label so that it appears nicely in the context menu
        return portactions

    # this function fetches all the port actions that will be run as terminal commands from the settings file
    def getSchedulerSettings(self):
        settings = []
        self.actions.beginGroup('SchedulerSettings')
        keys = self.actions.childKeys()
        for k in keys:
            settings.append([str(k), self.actions.value(k)[0], self.actions.value(k)[1]])
        self.actions.endGroup()
        return settings

    def getSettingsByGroup(self, name: str) -> dict:
        self.actions.beginGroup(name)
        settings = dict()
        keys = self.actions.childKeys()
        for k in keys:
            settings.update({str(k): str(self.actions.value(k))})
        self.actions.endGroup()
        log.debug("getSettingsByGroup name:{0}, result:{1}".format(str(name), str(settings)))
        return settings

    def backupAndSave(self, newSettings, saveBackup=True):
        conf_path = get_legion_conf_path()
        backup_dir = get_legion_backup_dir()
        os.makedirs(backup_dir, exist_ok=True)

        # Backup and save
        if saveBackup:
            log.info('Backing up old settings and saving new settings...')
            os.rename(
                conf_path,
                os.path.join(backup_dir, getTimestamp() + '-legion.conf')
            )
        else:
            log.info('Saving config...')

        self.actions = QtCore.QSettings(
            conf_path,
            QtCore.QSettings.Format.NativeFormat
        )

        self.actions.beginGroup('GeneralSettings')
        self.actions.setValue('default-terminal', newSettings.general_default_terminal)
        self.actions.setValue('tool-output-black-background', newSettings.general_tool_output_black_background)
        self.actions.setValue('screenshooter-timeout', newSettings.general_screenshooter_timeout)
        self.actions.setValue('web-services', newSettings.general_web_services)
        self.actions.setValue('enable-scheduler', newSettings.general_enable_scheduler)
        self.actions.setValue('enable-scheduler-on-import', newSettings.general_enable_scheduler_on_import)
        self.actions.setValue('max-fast-processes', newSettings.general_max_fast_processes)
        self.actions.setValue('max-slow-processes', newSettings.general_max_slow_processes)
        self.actions.setValue('notes-autosave-minutes', newSettings.general_notes_autosave_minutes)
        self.actions.endGroup()

        self.actions.beginGroup('BruteSettings')
        self.actions.setValue('store-cleartext-passwords-on-exit', newSettings.brute_store_cleartext_passwords_on_exit)
        self.actions.setValue('username-wordlist-path', newSettings.brute_username_wordlist_path)
        self.actions.setValue('password-wordlist-path', newSettings.brute_password_wordlist_path)
        self.actions.setValue('default-username', newSettings.brute_default_username)
        self.actions.setValue('default-password', newSettings.brute_default_password)
        self.actions.setValue('services', newSettings.brute_services)
        self.actions.setValue('no-username-services', newSettings.brute_no_username_services)
        self.actions.setValue('no-password-services', newSettings.brute_no_password_services)
        self.actions.endGroup()

        self.actions.beginGroup('ToolSettings')
        self.actions.setValue('nmap-path', newSettings.tools_path_nmap)
        self.actions.setValue('hydra-path', newSettings.tools_path_hydra)
        self.actions.setValue('texteditor-path', newSettings.tools_path_texteditor)
        self.actions.setValue('pyshodan-api-key', newSettings.tools_pyshodan_api_key)
        self.actions.setValue('responder-path', newSettings.tools_path_responder)
        self.actions.setValue('ntlmrelay-path', newSettings.tools_path_ntlmrelay)
        self.actions.endGroup()

        self.actions.beginGroup('StagedNmapSettings')
        self.actions.setValue('stage1-ports', newSettings.tools_nmap_stage1_ports)
        self.actions.setValue('stage2-ports', newSettings.tools_nmap_stage2_ports)
        self.actions.setValue('stage3-ports', newSettings.tools_nmap_stage3_ports)
        self.actions.setValue('stage4-ports', newSettings.tools_nmap_stage4_ports)
        self.actions.setValue('stage5-ports', newSettings.tools_nmap_stage5_ports)
        self.actions.setValue('stage6-ports', newSettings.tools_nmap_stage6_ports)
        self.actions.endGroup()

        self.actions.beginGroup('GUISettings')
        self.actions.setValue('process-tab-column-widths', newSettings.gui_process_tab_column_widths)
        self.actions.setValue('process-tab-detail', newSettings.gui_process_tab_detail)
        self.actions.endGroup()

        self.actions.beginGroup('HostActions')
        for a in newSettings.hostActions:
            self.actions.setValue(a[1], [a[0], a[2]])
        self.actions.endGroup()

        self.actions.beginGroup('PortActions')
        for a in newSettings.portActions:
            self.actions.setValue(a[1], [a[0], a[2], a[3]])
        self.actions.endGroup()

        self.actions.beginGroup('PortTerminalActions')
        for a in newSettings.portTerminalActions:
            self.actions.setValue(a[1], [a[0], a[2], a[3]])
        self.actions.endGroup()

        self.actions.beginGroup('SchedulerSettings')
        for tool in newSettings.automatedAttacks:
            self.actions.setValue(tool[0], [tool[1], tool[2]])
        self.actions.endGroup()

        self.actions.sync()


# This class first sets all the default settings and
# then overwrites them with the settings found in the configuration file
class Settings():
    def __init__(self, appSettings=None):

        # general
        self.general_default_terminal = "gnome-terminal"
        self.general_tool_output_black_background = "False"
        self.general_screenshooter_timeout = "15000"
        self.general_web_services = "http,https,ssl,soap,http-proxy,http-alt,https-alt"
        self.general_enable_scheduler = "True"
        self.general_enable_scheduler_on_import = "False"
        self.general_max_fast_processes = "10"
        self.general_max_slow_processes = "10"
        # Notes auto-save interval. Set to "0" to disable.
        self.general_notes_autosave_minutes = "2"

        # brute
        self.brute_store_cleartext_passwords_on_exit = "True"
        self.brute_username_wordlist_path = "/usr/share/wordlists/"
        self.brute_password_wordlist_path = "/usr/share/wordlists/"
        self.brute_default_username = "root"
        self.brute_default_password = "password"
        self.brute_services = "asterisk,afp,cisco,cisco-enable,cvs,firebird,ftp,ftps,http-head,http-get," + \
                              "https-head,https-get,http-get-form,http-post-form,https-get-form," + \
                              "https-post-form,http-proxy,http-proxy-urlenum,icq,imap,imaps,irc,ldap2,ldap2s," + \
                              "ldap3,ldap3s,ldap3-crammd5,ldap3-crammd5s,ldap3-digestmd5,ldap3-digestmd5s," + \
                              "mssql,mysql,ncp,nntp,oracle-listener,oracle-sid,pcanywhere,pcnfs,pop3,pop3s," + \
                              "postgres,rdp,rexec,rlogin,rsh,s7-300,sip,smb,smtp,smtps,smtp-enum,snmp,socks5," + \
                              "ssh,sshkey,svn,teamspeak,telnet,telnets,vmauthd,vnc,xmpp"
        self.brute_no_username_services = "cisco,cisco-enable,oracle-listener,s7-300,snmp,vnc"
        self.brute_no_password_services = "oracle-sid,rsh,smtp-enum"

        # tools
        self.tools_nmap_stage1_ports = "T:80,443"
        self.tools_nmap_stage2_ports = "T:25,135,137,139,445,1433,3306,5432,U:137,161,162,1434"
        self.tools_nmap_stage3_ports = "Vulners,CVE"
        self.tools_nmap_stage4_ports = "T:23,21,22,110,111,2049,3389,8080,U:500,5060"
        self.tools_nmap_stage5_ports = "T:0-20,24,26-79,81-109,112-134,136,138,140-442,444,446-1432,1434-2048," + \
                                       "2050-3305,3307-3388,3390-5431,5433-8079,8081-29999"
        self.tools_nmap_stage6_ports = "T:30000-65535"

        self.tools_path_nmap = "/sbin/nmap"
        self.tools_path_hydra = "/usr/bin/hydra"
        self.tools_path_texteditor = "/usr/bin/xdg-open"
        self.tools_pyshodan_api_key = ""
        self.tools_path_responder = "/usr/bin/responder"
        self.tools_path_ntlmrelay = "/usr/bin/ntlmrelayx.py"
        self.tools_path_responder = "responder"
        self.tools_path_ntlmrelay = "ntlmrelayx.py"

        # GUI settings
        self.gui_process_tab_column_widths = "125,0,100,150,100,100,100,100,100,100,100,100,100,100,100,100,100"
        self.gui_process_tab_detail = False

        self.hostActions = []
        self.portActions = []
        self.portTerminalActions = []
        self.stagedNmapSettings = []
        self.automatedAttacks = []

        # now that all defaults are set, overwrite with whatever was in the .conf file (stored in appSettings)
        if appSettings:
            try:
                self.generalSettings = appSettings.getGeneralSettings()
                self.bruteSettings = appSettings.getBruteSettings()
                self.stagedNmapSettings = appSettings.getStagedNmapSettings()
                self.toolSettings = appSettings.getToolSettings()
                self.guiSettings = appSettings.getGUISettings()
                self.hostActions = appSettings.getHostActions()
                self.portActions = appSettings.getPortActions()
                self.portTerminalActions = appSettings.getPortTerminalActions()
                self.automatedAttacks = appSettings.getSchedulerSettings()

                # general
                self.general_default_terminal = self.generalSettings['default-terminal']
                self.general_tool_output_black_background = self.generalSettings['tool-output-black-background']
                self.general_screenshooter_timeout = self.generalSettings['screenshooter-timeout']
                self.general_web_services = self.generalSettings['web-services']
                self.general_enable_scheduler = self.generalSettings['enable-scheduler']
                self.general_enable_scheduler_on_import = self.generalSettings['enable-scheduler-on-import']
                self.general_max_fast_processes = self.generalSettings['max-fast-processes']
                self.general_max_slow_processes = self.generalSettings['max-slow-processes']
                self.general_notes_autosave_minutes = self.generalSettings.get(
                    'notes-autosave-minutes',
                    self.general_notes_autosave_minutes
                )

                # brute
                self.brute_store_cleartext_passwords_on_exit = self.bruteSettings['store-cleartext-passwords-on-exit']
                self.brute_username_wordlist_path = self.bruteSettings['username-wordlist-path']
                self.brute_password_wordlist_path = self.bruteSettings['password-wordlist-path']
                self.brute_default_username = self.bruteSettings['default-username']
                self.brute_default_password = self.bruteSettings['default-password']
                self.brute_services = self.bruteSettings['services']
                self.brute_no_username_services = self.bruteSettings['no-username-services']
                self.brute_no_password_services = self.bruteSettings['no-password-services']

                # tools
                self.tools_nmap_stage1_ports = self.stagedNmapSettings['stage1-ports']
                self.tools_nmap_stage2_ports = self.stagedNmapSettings['stage2-ports']
                self.tools_nmap_stage3_ports = self.stagedNmapSettings['stage3-ports']
                self.tools_nmap_stage4_ports = self.stagedNmapSettings['stage4-ports']
                self.tools_nmap_stage5_ports = self.stagedNmapSettings['stage5-ports']
                self.tools_nmap_stage6_ports = self.stagedNmapSettings['stage6-ports']

                self.tools_path_nmap = self.toolSettings['nmap-path']
                self.tools_path_hydra = self.toolSettings['hydra-path']
                self.tools_path_texteditor = self.toolSettings['texteditor-path']
                self.tools_pyshodan_api_key = self.toolSettings['pyshodan-api-key']
                self.tools_path_responder = self.toolSettings.get('responder-path', self.tools_path_responder)
                self.tools_path_ntlmrelay = self.toolSettings.get('ntlmrelay-path', self.tools_path_ntlmrelay)
                self.tools_path_responder = self.toolSettings.get('responder-path', self.tools_path_responder)
                self.tools_path_ntlmrelay = self.toolSettings.get('ntlmrelay-path', self.tools_path_ntlmrelay)

                # gui
                self.gui_process_tab_column_widths = self.guiSettings['process-tab-column-widths']
                self.gui_process_tab_detail = self.guiSettings['process-tab-detail']

            except KeyError as e:
                log.info('Something went wrong while loading the configuration file. Falling back to default ' +
                         'settings for some settings.')
                log.info('Go to the settings menu to fix the issues!')
                log.error(str(e))

    def __eq__(self, other):  # returns false if settings objects are different
        if type(other) is type(self):
            return self.__dict__ == other.__dict__
        return False


if __name__ == "__main__":
    settings = AppSettings()
    s = Settings(settings)
    s2 = Settings(settings)
    log.info(s == s2)
    s2.general_default_terminal = 'whatever'
    log.info(s == s2)
