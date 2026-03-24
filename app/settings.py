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

from app.core.config_store import IniSettingsStore
from app.core.common import sortArrayWithArray
from app.hostsfile import normalize_hostname_alias
from app.logging.legionLog import getAppLogger
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
    HOST_SERVICE_SCOPE = "host"
    REMOTE_SCREEN_SERVICE_SCOPE = "ms-wbt-server,rdp,vmrdp,vnc,vnc-http,rfb"
    SCREENSHOT_SERVICE_SCOPE = f"{WEB_SERVICE_SCOPE},{REMOTE_SCREEN_SERVICE_SCOPE}"
    BANNER_COMMAND = (
        "LEGION_BANNER_TARGET=[IP] LEGION_BANNER_PORT=[PORT] "
        "LEGION_BANNER_PROTOCOL=tcp python3 -m app.banner_probe"
    )
    ALLOWED_NONZERO_EXIT_CODES = {
        "nikto": {1},
        "wpscan": {4},
    }
    DISABLED_PORT_ACTION_IDS = {
        "http-drupal-modules.nse",
        "http-wapiti",
        "http-vuln-zimbra-lfi.nse",
        "http-wordpress-plugins.nse",
        "https-wapiti",
        "sslyze",
    }
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
        "(nmap -Pn -n -sV -p [PORT] --script=vuln,vulners --stats-every 15s [IP] -oA [OUTPUT] || "
        "nmap -Pn -n -sV -p [PORT] --script=vuln --stats-every 15s [IP] -oA [OUTPUT])"
    )
    NUCLEI_WEB_COMMAND = (
        "(command -v nuclei >/dev/null 2>&1 && "
        "(nuclei -as -stats -si 15 -u https://[IP]:[PORT] -ni -o [OUTPUT].txt || "
        "nuclei -as -stats -si 15 -u http://[IP]:[PORT] -ni -o [OUTPUT].txt)) || "
        "echo nuclei not found"
    )
    NUCLEI_CVES_COMMAND = (
        "(command -v nuclei >/dev/null 2>&1 && "
        "(nuclei -tags cve -stats -si 15 -u https://[IP]:[PORT] -ni -o [OUTPUT].txt || "
        "nuclei -tags cve -stats -si 15 -u http://[IP]:[PORT] -ni -o [OUTPUT].txt)) || "
        "echo nuclei not found"
    )
    NUCLEI_EXPOSURES_COMMAND = (
        "(command -v nuclei >/dev/null 2>&1 && "
        "(nuclei -tags exposure,panel -stats -si 15 -u https://[IP]:[PORT] -ni -o [OUTPUT].txt || "
        "nuclei -tags exposure,panel -stats -si 15 -u http://[IP]:[PORT] -ni -o [OUTPUT].txt)) || "
        "echo nuclei not found"
    )
    NUCLEI_WORDPRESS_COMMAND = (
        "(command -v nuclei >/dev/null 2>&1 && "
        "(nuclei -tags wordpress,wp-plugin -stats -si 15 -u https://[IP]:[PORT] -ni -o [OUTPUT].txt || "
        "nuclei -tags wordpress,wp-plugin -stats -si 15 -u http://[IP]:[PORT] -ni -o [OUTPUT].txt)) || "
        "echo nuclei not found"
    )
    NUCLEI_CLOUD_COMMAND = (
        "(command -v nuclei >/dev/null 2>&1 && "
        "nuclei -tags cloud,aws,azure,gcp -stats -si 15 -u [WEB_URL] -ni -o [OUTPUT].txt) || "
        "echo nuclei not found"
    )
    NUCLEI_AWS_STORAGE_COMMAND = (
        "(command -v nuclei >/dev/null 2>&1 && "
        "nuclei -tags aws,s3,bucket,storage -stats -si 15 -u [WEB_URL] -ni -o [OUTPUT].txt) || "
        "echo nuclei not found"
    )
    NUCLEI_AZURE_STORAGE_COMMAND = (
        "(command -v nuclei >/dev/null 2>&1 && "
        "nuclei -tags azure,blob,storage -stats -si 15 -u [WEB_URL] -ni -o [OUTPUT].txt) || "
        "echo nuclei not found"
    )
    NUCLEI_GCP_STORAGE_COMMAND = (
        "(command -v nuclei >/dev/null 2>&1 && "
        "nuclei -tags gcp,gcs,bucket,storage -stats -si 15 -u [WEB_URL] -ni -o [OUTPUT].txt) || "
        "echo nuclei not found"
    )
    NUCLEI_AWS_RDS_COMMAND = (
        "(command -v nuclei >/dev/null 2>&1 && "
        "nuclei -tags aws,rds,database -stats -si 15 -target [IP]:[PORT] -ni -o [OUTPUT].txt) || "
        "echo nuclei not found"
    )
    NUCLEI_AWS_AURORA_COMMAND = (
        "(command -v nuclei >/dev/null 2>&1 && "
        "nuclei -tags aws,aurora,database -stats -si 15 -target [IP]:[PORT] -ni -o [OUTPUT].txt) || "
        "echo nuclei not found"
    )
    NUCLEI_AZURE_COSMOS_COMMAND = (
        "(command -v nuclei >/dev/null 2>&1 && "
        "nuclei -tags azure,cosmos,cosmosdb,database -stats -si 15 -u [WEB_URL] -ni -o [OUTPUT].txt) || "
        "echo nuclei not found"
    )
    NUCLEI_GCP_CLOUDSQL_COMMAND = (
        "(command -v nuclei >/dev/null 2>&1 && "
        "nuclei -tags gcp,cloudsql,database -stats -si 15 -target [IP]:[PORT] -ni -o [OUTPUT].txt) || "
        "echo nuclei not found"
    )
    MYSQL_INFO_COMMAND = (
        "nmap -Pn [IP] -p [PORT] --script=mysql-info.nse --script-args=unsafe=1 "
        "--stats-every 15s -vv -oA [OUTPUT]"
    )
    PGSQL_INFO_COMMAND = (
        "nmap -Pn [IP] -p [PORT] --script=pgsql-info.nse --script-args=unsafe=1 "
        "--stats-every 15s -vv -oA [OUTPUT]"
    )
    MSSQL_INFO_COMMAND = (
        "nmap -Pn [IP] -p [PORT] --script=ms-sql-info.nse --script-args=unsafe=1 "
        "--stats-every 15s -vv -oA [OUTPUT]"
    )
    CURL_HEADERS_COMMAND = (
        "(command -v curl >/dev/null 2>&1 && "
        "(curl -k -I --max-time 20 https://[IP]:[PORT] > [OUTPUT].txt || "
        "curl -I --max-time 20 http://[IP]:[PORT] > [OUTPUT].txt)) || "
        "echo curl not found"
    )
    CURL_OPTIONS_COMMAND = (
        "(command -v curl >/dev/null 2>&1 && "
        "(curl -k -X OPTIONS -i --max-time 20 https://[IP]:[PORT] > [OUTPUT].txt || "
        "curl -X OPTIONS -i --max-time 20 http://[IP]:[PORT] > [OUTPUT].txt)) || "
        "echo curl not found"
    )
    CURL_ROBOTS_COMMAND = (
        "(command -v curl >/dev/null 2>&1 && "
        "(curl -k --max-time 20 https://[IP]:[PORT]/robots.txt -o [OUTPUT].txt || "
        "curl --max-time 20 http://[IP]:[PORT]/robots.txt -o [OUTPUT].txt)) || "
        "echo curl not found"
    )
    HTTPX_COMMAND = (
        "(command -v httpx >/dev/null 2>&1 && "
        "httpx -silent -json -title -tech-detect -web-server -status-code -content-type "
        "-u [WEB_URL] -o [OUTPUT].jsonl) || "
        "echo httpx not found"
    )
    SUBFINDER_COMMAND = (
        "(command -v subfinder >/dev/null 2>&1 && "
        "subfinder -silent -recursive -duc -max-time 5 -oJ -d [IP] -o [OUTPUT].jsonl) || "
        "echo subfinder not found"
    )
    CHAOS_COMMAND = (
        "(test -n [CHAOS_API_KEY] && command -v chaos >/dev/null 2>&1 && "
        "chaos -d [ROOT_DOMAIN] -silent -json -key [CHAOS_API_KEY] -o [OUTPUT].jsonl) || "
        "echo chaos not configured"
    )
    GRAYHATWARFARE_COMMAND = (
        "(test -n [GRAYHAT_API_KEY] && "
        "python3 -m app.grayhatwarfare_probe --domain [ROOT_DOMAIN] --api-key [GRAYHAT_API_KEY] --output [OUTPUT].json) || "
        "echo grayhatwarfare not configured"
    )
    SHODAN_ENRICHMENT_COMMAND = (
        "(test -n [SHODAN_API_KEY] && "
        "python3 -m app.shodan_probe --target [IP] --api-key [SHODAN_API_KEY] --output [OUTPUT].json) || "
        "echo shodan not configured"
    )
    NIKTO_COMMAND = (
        "(command -v nikto >/dev/null 2>&1 && "
        "nikto -h [WEB_URL] -nointeractive -Format txt -output [OUTPUT].txt -C all) || "
        "echo nikto not found"
    )
    WAFW00F_COMMAND = (
        "(command -v wafw00f >/dev/null 2>&1 && "
        "(wafw00f https://[IP]:[PORT] || wafw00f http://[IP]:[PORT])) || "
        "echo wafw00f not found"
    )
    SSLSCAN_COMMAND = "sslscan --no-failed [IP]:[PORT]"
    TESTSSL_SH_COMMAND = (
        "((command -v testssl.sh >/dev/null 2>&1 && "
        "testssl.sh --quiet --warnings off --connect-timeout 10 --openssl-timeout 10 "
        "--jsonfile-pretty [OUTPUT].json [IP]:[PORT] > [OUTPUT].txt 2>&1) || "
        "(command -v testssl >/dev/null 2>&1 && "
        "testssl --quiet --warnings off --connect-timeout 10 --openssl-timeout 10 "
        "--jsonfile-pretty [OUTPUT].json [IP]:[PORT] > [OUTPUT].txt 2>&1)) || "
        "echo testssl.sh not found"
    )
    WPSCAN_COMMAND = (
        "(command -v wpscan >/dev/null 2>&1 && "
        "wpscan --url [WEB_URL] --disable-tls-checks --no-update --format json --output [OUTPUT].json) || "
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
    SAMRDUMP_COMMAND = (
        "(command -v impacket-samrdump >/dev/null 2>&1 && "
        "impacket-samrdump -no-pass -port [PORT] [IP] > [OUTPUT].txt 2>&1) || "
        "([ -f /usr/share/doc/python3-impacket/examples/samrdump.py ] && "
        "python3 /usr/share/doc/python3-impacket/examples/samrdump.py -no-pass -port [PORT] [IP] > [OUTPUT].txt 2>&1) || "
        "([ -f /usr/share/doc/python-impacket-doc/examples/samrdump.py ] && "
        "python3 /usr/share/doc/python-impacket-doc/examples/samrdump.py -no-pass -port [PORT] [IP] > [OUTPUT].txt 2>&1) || "
        "echo samrdump not found"
    )
    WHATWEB_COMMAND = (
        "(command -v whatweb >/dev/null 2>&1 && "
        "whatweb [WEB_URL] --color=never --log-brief=[OUTPUT].txt) || "
        "echo whatweb not found"
    )
    DIRSEARCH_COMMAND = (
        "(command -v dirsearch >/dev/null 2>&1 && "
        "dirsearch -u [WEB_URL]/ --quiet-mode --format=json --output=[OUTPUT].json) || "
        "echo dirsearch not found"
    )
    FFUF_COMMAND = (
        "(command -v ffuf >/dev/null 2>&1 && "
        "ffuf -u [WEB_URL]/FUZZ -w /usr/share/wordlists/dirb/common.txt "
        "-s -of json -o [OUTPUT].json) || "
        "echo ffuf not found"
    )
    KATANA_COMMAND = (
        "(command -v katana >/dev/null 2>&1 && "
        "katana -u [WEB_URL] -silent -jsonl -d 2 -jc -kf robotstxt,sitemapxml -c 5 -p 1 -rl 5 -o [OUTPUT].jsonl) || "
        "echo katana not found"
    )
    ENUM4LINUX_NG_COMMAND = (
        "if command -v enum4linux-ng >/dev/null 2>&1; then "
        "enum4linux-ng -A -oJ [OUTPUT] [IP]; "
        "else echo enum4linux-ng not found; fi"
    )
    SMBMAP_COMMAND = (
        "if command -v smbmap >/dev/null 2>&1; then "
        "smbmap -H [IP] -P [PORT] --no-write-check -q | tee [OUTPUT].txt; "
        "else echo smbmap not found; fi"
    )
    RPCCLIENT_ENUM_COMMAND = (
        "if command -v rpcclient >/dev/null 2>&1; then "
        "rpcclient [IP] -p [PORT] -U '%' -c 'srvinfo;enumdomusers;netshareenumall' > [OUTPUT].txt; "
        "else echo rpcclient not found; fi"
    )
    RESPONDER_COMMAND = "responder -I <interface> -w -F"
    NTLMRELAYX_COMMAND = "impacket-ntlmrelayx -t smb://[IP] -smb2support"
    NETEXEC_COMMAND = (
        "if command -v netexec >/dev/null 2>&1; then "
        "netexec smb [IP] --port [PORT] -u '' -p '' --shares --users --pass-pol 2>&1 | tee [OUTPUT].txt; "
        "elif command -v nxc >/dev/null 2>&1; then "
        "nxc smb [IP] --port [PORT] -u '' -p '' --shares --users --pass-pol 2>&1 | tee [OUTPUT].txt; "
        "else echo netexec not found; fi"
    )
    BASELINE_WEB_PORT_ACTIONS = {
        "httpx": ("Run httpx", HTTPX_COMMAND, WEB_SERVICE_SCOPE),
        "whatweb": ("Run whatweb", WHATWEB_COMMAND, WEB_SERVICE_SCOPE),
        "whatweb-http": ("Run whatweb (http)", WHATWEB_COMMAND, "http,soap,http-proxy,http-alt"),
        "whatweb-https": ("Run whatweb (https)", WHATWEB_COMMAND, "https,ssl,https-alt"),
        "nikto": ("Run nikto", NIKTO_COMMAND, WEB_SERVICE_SCOPE),
        "wafw00f": ("Run wafw00f", WAFW00F_COMMAND, "https,ssl,https-alt"),
        "sslscan": ("Run sslscan", SSLSCAN_COMMAND, "https,ssl,https-alt"),
        "testssl.sh": ("Run testssl.sh", TESTSSL_SH_COMMAND, "https,ssl,ms-wbt-server,imap,pop3,smtp,https-alt"),
        "nuclei-cves": ("Run nuclei CVE follow-up", NUCLEI_CVES_COMMAND, WEB_SERVICE_SCOPE),
        "nuclei-exposures": ("Run nuclei exposure/panel follow-up", NUCLEI_EXPOSURES_COMMAND, WEB_SERVICE_SCOPE),
        "nuclei-wordpress": ("Run nuclei WordPress follow-up", NUCLEI_WORDPRESS_COMMAND, WEB_SERVICE_SCOPE),
        "curl-headers": ("Collect HTTP headers (curl)", CURL_HEADERS_COMMAND, WEB_SERVICE_SCOPE),
        "curl-options": ("Collect HTTP OPTIONS response (curl)", CURL_OPTIONS_COMMAND, WEB_SERVICE_SCOPE),
        "curl-robots": ("Fetch robots.txt (curl)", CURL_ROBOTS_COMMAND, WEB_SERVICE_SCOPE),
        "wpscan": ("Run wpscan", WPSCAN_COMMAND, "http,https,ssl,https-alt"),
        "dirsearch": ("Run dirsearch", DIRSEARCH_COMMAND, WEB_SERVICE_SCOPE),
        "ffuf": ("Run ffuf", FFUF_COMMAND, WEB_SERVICE_SCOPE),
        "katana": ("Run katana", KATANA_COMMAND, WEB_SERVICE_SCOPE),
    }
    EXTERNAL_RECON_PORT_ACTIONS = {
        "subfinder": ("Run subfinder passive subdomain discovery", SUBFINDER_COMMAND, HOST_SERVICE_SCOPE),
        "chaos": ("Run Chaos passive subdomain discovery", CHAOS_COMMAND, HOST_SERVICE_SCOPE),
        "grayhatwarfare": ("Run Grayhat Warfare bucket/file search", GRAYHATWARFARE_COMMAND, HOST_SERVICE_SCOPE),
        "shodan-enrichment": ("Run Shodan hostname enrichment", SHODAN_ENRICHMENT_COMMAND, HOST_SERVICE_SCOPE),
        "nuclei-cloud": ("Run nuclei cloud exposure follow-up", NUCLEI_CLOUD_COMMAND, WEB_SERVICE_SCOPE),
        "nuclei-aws-storage": ("Run nuclei AWS storage follow-up", NUCLEI_AWS_STORAGE_COMMAND, WEB_SERVICE_SCOPE),
        "nuclei-azure-storage": ("Run nuclei Azure storage follow-up", NUCLEI_AZURE_STORAGE_COMMAND, WEB_SERVICE_SCOPE),
        "nuclei-gcp-storage": ("Run nuclei GCP storage follow-up", NUCLEI_GCP_STORAGE_COMMAND, WEB_SERVICE_SCOPE),
        "nuclei-aws-rds": ("Run nuclei AWS RDS follow-up", NUCLEI_AWS_RDS_COMMAND, "mysql,postgres,postgresql,ms-sql,ms-sql-s,codasrv-se"),
        "nuclei-aws-aurora": ("Run nuclei AWS Aurora follow-up", NUCLEI_AWS_AURORA_COMMAND, "mysql,postgres,postgresql"),
        "nuclei-azure-cosmos": ("Run nuclei Azure Cosmos DB follow-up", NUCLEI_AZURE_COSMOS_COMMAND, WEB_SERVICE_SCOPE),
        "nuclei-gcp-cloudsql": ("Run nuclei GCP Cloud SQL follow-up", NUCLEI_GCP_CLOUDSQL_COMMAND, "mysql,postgres,postgresql,ms-sql,ms-sql-s,codasrv-se"),
    }
    BASELINE_INTERNAL_PORT_ACTIONS = {
        "enum4linux-ng": ("Run enum4linux-ng", ENUM4LINUX_NG_COMMAND, "netbios-ssn,microsoft-ds,smb"),
        "smbmap": ("Run smbmap", SMBMAP_COMMAND, "netbios-ssn,microsoft-ds,smb"),
        "rpcclient-enum": ("Run rpcclient SMB enumeration", RPCCLIENT_ENUM_COMMAND, "netbios-ssn,microsoft-ds,smb"),
        "netexec": ("Run netexec", NETEXEC_COMMAND, "netbios-ssn,microsoft-ds,smb"),
        "mysql-info.nse": ("Run mysql-info.nse", MYSQL_INFO_COMMAND, "mysql"),
        "pgsql-info.nse": ("Run pgsql-info.nse", PGSQL_INFO_COMMAND, "postgres,postgresql"),
        "ms-sql-info.nse": ("Run ms-sql-info.nse", MSSQL_INFO_COMMAND, "ms-sql,ms-sql-s,codasrv-se"),
        "responder": (
            "Prepare Responder capture workflow",
            RESPONDER_COMMAND,
            "netbios-ssn,microsoft-ds,smb,ldap,kerberos,winrm",
        ),
        "ntlmrelayx": (
            "Prepare ntlmrelayx relay workflow",
            NTLMRELAYX_COMMAND,
            "netbios-ssn,microsoft-ds,smb,ldap,kerberos,winrm",
        ),
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
        self.actions = IniSettingsStore(config_path)
        self._apply_default_action_migrations()

    def _apply_default_action_migrations(self):
        changed = False
        changed = self._migrate_host_actions() or changed
        changed = self._migrate_port_actions() or changed
        changed = self._migrate_port_terminal_actions() or changed
        changed = self._migrate_scheduler_settings() or changed
        if changed:
            self.actions.sync()
            log.info("Applied legion.conf action migration updates (nmap stats, banner, nuclei, vuln, web-content-discovery).")

    def _migrate_host_actions(self):
        changed = False
        self.actions.beginGroup('HostActions')
        try:
            keys = self.actions.childKeys()
            for key in keys:
                value = self.actions.value(key)
                if not isinstance(value, (list, tuple)) or len(value) < 2:
                    continue
                label = str(value[0] or "")
                command = str(value[1] or "")
                updated_command = self._normalize_action_command(str(key), command)
                if updated_command != command:
                    self.actions.setValue(str(key), [label, updated_command])
                    changed = True
        finally:
            self.actions.endGroup()
        return changed

    def _migrate_port_actions(self):
        changed = False
        self.actions.beginGroup('PortActions')
        try:
            expected_scopes = {
                str(key): str(value[2] or "")
                for key, value in {
                    **self.BASELINE_WEB_PORT_ACTIONS,
                    **self.EXTERNAL_RECON_PORT_ACTIONS,
                    **self.BASELINE_INTERNAL_PORT_ACTIONS,
                }.items()
            }
            for key in sorted(self.DISABLED_PORT_ACTION_IDS):
                if self.actions.value(key) is not None:
                    self.actions.remove(key)
                    changed = True

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

            for key, value in {
                **self.BASELINE_WEB_PORT_ACTIONS,
                **self.EXTERNAL_RECON_PORT_ACTIONS,
                **self.BASELINE_INTERNAL_PORT_ACTIONS,
            }.items():
                if self.actions.value(key) is None:
                    self.actions.setValue(key, [value[0], value[1], value[2]])
                    changed = True

            keys = self.actions.childKeys()
            for key in keys:
                value = self.actions.value(key)
                if not isinstance(value, (list, tuple)) or len(value) < 2:
                    continue
                label = str(value[0] or "")
                command = str(value[1] or "")
                scope = str(value[2] or "") if len(value) > 2 else ""
                updated_command = self._normalize_action_command(str(key), command)
                if updated_command != command:
                    self.actions.setValue(str(key), [label, updated_command, scope])
                    changed = True
                    command = updated_command
                expected_scope = str(expected_scopes.get(str(key), "") or "")
                if expected_scope and scope != expected_scope:
                    self.actions.setValue(str(key), [label, command, expected_scope])
                    changed = True
        finally:
            self.actions.endGroup()
        return changed

    @classmethod
    def _normalize_action_command(cls, tool_id: str, command: str) -> str:
        normalized_tool = str(tool_id or "").strip().lower()
        normalized = str(command or "")
        if normalized_tool == "banner":
            normalized = cls._ensure_banner_command(normalized)
        if normalized_tool == "nuclei-web":
            normalized = cls._ensure_nuclei_auto_scan(normalized)
        elif "nuclei" in normalized_tool or "nuclei" in normalized.lower():
            normalized = cls._ensure_nuclei_command(normalized, automatic_scan=False)
        if normalized_tool == "web-content-discovery":
            normalized = cls._ensure_web_content_discovery_command(normalized)
        if normalized_tool == "httpx":
            normalized = cls._ensure_httpx_command(normalized)
        if normalized_tool == "subfinder":
            normalized = cls._ensure_subfinder_command(normalized)
        if normalized_tool == "chaos":
            normalized = cls.CHAOS_COMMAND
        if normalized_tool in {"whatweb", "whatweb-http", "whatweb-https"}:
            normalized = cls._ensure_whatweb_command(normalized)
        if normalized_tool == "nikto":
            normalized = cls._ensure_nikto_command(normalized)
        if normalized_tool == "katana":
            normalized = cls._ensure_katana_command(normalized)
        if normalized_tool == "wpscan":
            normalized = cls._ensure_wpscan_command(normalized)
        if normalized_tool == "dirsearch":
            normalized = cls._ensure_dirsearch_command(normalized)
        if normalized_tool == "ffuf":
            normalized = cls._ensure_ffuf_command(normalized)
        if "hydra" in normalized.lower():
            normalized = cls._ensure_hydra_command(normalized)
        if normalized_tool == "enum4linux-ng":
            normalized = cls._ensure_enum4linux_ng_command(normalized)
        if normalized_tool == "smbmap":
            normalized = cls._ensure_smbmap_command(normalized)
        if normalized_tool == "rpcclient-enum":
            normalized = cls._ensure_rpcclient_enum_command(normalized)
        if normalized_tool == "netexec":
            normalized = cls._ensure_netexec_command(normalized)
        if normalized_tool == "mysql-info.nse":
            normalized = cls.MYSQL_INFO_COMMAND
        if normalized_tool == "pgsql-info.nse":
            normalized = cls.PGSQL_INFO_COMMAND
        if normalized_tool == "ms-sql-info.nse":
            normalized = cls.MSSQL_INFO_COMMAND
        if normalized_tool == "responder":
            normalized = cls._ensure_responder_command(normalized)
        if normalized_tool == "ntlmrelayx":
            normalized = cls._ensure_ntlmrelayx_command(normalized)
        if normalized_tool == "samrdump":
            normalized = cls.SAMRDUMP_COMMAND
        if normalized_tool == "smb-enum-users-rpc":
            normalized = cls._canonicalize_legacy_rpcclient_action("enumdomusers")
        if normalized_tool == "smb-null-sessions":
            normalized = cls._canonicalize_legacy_rpcclient_action("srvinfo")
        if normalized_tool == "smb-enum-admins":
            normalized = cls._canonicalize_legacy_net_rpc_group_members_action("Domain Admins")
        if normalized_tool == "snmp-brute":
            normalized = cls._canonicalize_legacy_snmp_brute_action()
        if normalized_tool == "rpcclient":
            normalized = cls._ensure_terminal_rpcclient_command(normalized)
        if "wapiti" in normalized.lower():
            scheme = "https" if "https" in normalized_tool else "http"
            normalized = cls._ensure_wapiti_command(normalized, scheme=scheme)
        if "nmap" in normalized.lower():
            normalized = cls._ensure_nmap_stats_every(normalized)
        return normalized

    def _migrate_scheduler_settings(self):
        changed = False
        self.actions.beginGroup('SchedulerSettings')
        try:
            for key in sorted(self.DISABLED_PORT_ACTION_IDS):
                if self.actions.value(key) is not None:
                    self.actions.remove(key)
                    changed = True

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

            for tool_id, scope in (
                    ("whatweb", self.WEB_SERVICE_SCOPE),
                    ("httpx", self.WEB_SERVICE_SCOPE),
                    ("whatweb-http", "http,soap,http-proxy,http-alt"),
                    ("whatweb-https", "https,ssl,https-alt"),
                    ("nikto", self.WEB_SERVICE_SCOPE),
                    ("wafw00f", "https,ssl,https-alt"),
                    ("sslscan", "https,ssl,https-alt"),
                    ("testssl.sh", "https,ssl,ms-wbt-server,imap,pop3,smtp,https-alt"),
                    ("nuclei-cves", self.WEB_SERVICE_SCOPE),
                    ("nuclei-exposures", self.WEB_SERVICE_SCOPE),
                    ("nuclei-wordpress", self.WEB_SERVICE_SCOPE),
                    ("curl-headers", self.WEB_SERVICE_SCOPE),
                    ("curl-options", self.WEB_SERVICE_SCOPE),
                    ("curl-robots", self.WEB_SERVICE_SCOPE),
                    ("wpscan", "http,https,ssl,https-alt"),
                    ("dirsearch", self.WEB_SERVICE_SCOPE),
                    ("ffuf", self.WEB_SERVICE_SCOPE),
                    ("katana", self.WEB_SERVICE_SCOPE),
                    ("enum4linux-ng", "netbios-ssn,microsoft-ds,smb"),
                    ("smbmap", "netbios-ssn,microsoft-ds,smb"),
                    ("rpcclient-enum", "netbios-ssn,microsoft-ds,smb"),
                    ("netexec", "netbios-ssn,microsoft-ds,smb"),
                    ("mysql-info.nse", "mysql"),
                    ("pgsql-info.nse", "postgres,postgresql"),
                    ("ms-sql-info.nse", "ms-sql,ms-sql-s,codasrv-se"),
            ):
                if self.actions.value(tool_id) is None:
                    self.actions.setValue(tool_id, [scope, 'tcp'])
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

    def _migrate_port_terminal_actions(self):
        changed = False
        self.actions.beginGroup('PortTerminalActions')
        try:
            keys = self.actions.childKeys()
            for key in keys:
                value = self.actions.value(key)
                if not isinstance(value, (list, tuple)) or len(value) < 2:
                    continue
                label = str(value[0] or "")
                command = str(value[1] or "")
                scope = str(value[2] or "") if len(value) > 2 else ""
                updated_command = self._normalize_action_command(str(key), command)
                if updated_command != command:
                    self.actions.setValue(str(key), [label, updated_command, scope])
                    changed = True
        finally:
            self.actions.endGroup()
        return changed

    @staticmethod
    def _ensure_nuclei_command(command: str, automatic_scan: bool = False) -> str:
        raw = str(command or "")
        if "nuclei" not in raw.lower():
            return raw
        probe_marker = "__LEGION_NUCLEI_PROBE__"
        normalized = re.sub(r"(?i)command\s+-v\s+nuclei", f"command -v {probe_marker}", raw)
        if automatic_scan:
            # Only patch direct scan invocations (`nuclei -u ...`), not probe checks
            # like `command -v nuclei` and not tokens embedded in output filenames.
            normalized = re.sub(
                r"(?i)\bnuclei\b(?!\s+-as\b)(?=[^|;&()\n]*\s+-u\b)",
                "nuclei -as",
                normalized,
            )
        normalized = re.sub(
            r"(?i)\bnuclei(?:\s+-as)?(?![^|;&()\n]*\s+-stats\b)(?=[^|;&()\n]*\s+-u\b)",
            lambda match: f"{match.group(0)} -stats",
            normalized,
        )
        normalized = re.sub(
            r"(?i)(\s(?:-si|--stats-interval)\b(?:\s+|=))\S+",
            lambda match: f"{match.group(1)}15",
            normalized,
        )
        normalized = re.sub(
            r"(?i)\bnuclei(?:\s+-as)?(?:\s+-stats)?(?![^|;&()\n]*\s+(?:-si|--stats-interval)(?:\s+|=))(?=[^|;&()\n]*\s+-u\b)",
            lambda match: f"{match.group(0)} -si 15",
            normalized,
        )
        normalized = re.sub(
            r"(?i)\bnuclei(?:\s+-as)?(?:\s+-stats)?(?:\s+-si\s+15)?(?![^|;&()\n]*\s+(?:-silent|--silent)\b)(?=[^|;&()\n]*\s+-u\b)",
            lambda match: f"{match.group(0)} -silent",
            normalized,
        )
        normalized = re.sub(r"(?i)(?<!\S)--?no-color\b", "", normalized)
        normalized = re.sub(r"[ \t]{2,}", " ", normalized)
        return normalized.replace(probe_marker, "nuclei")

    @staticmethod
    def _ensure_nuclei_auto_scan(command: str) -> str:
        return AppSettings._ensure_nuclei_command(command, automatic_scan=True)

    @staticmethod
    def _ensure_banner_command(command: str) -> str:
        raw = str(command or "").strip()
        lowered = raw.lower()
        if "nc" not in lowered and "netcat" not in lowered:
            return raw
        if "[ip]" not in lowered or "[port]" not in lowered:
            return raw
        protocol = "udp" if re.search(r"(?i)(?:^|\s)-u(?:\s|$)", raw) else "tcp"
        return AppSettings.BANNER_COMMAND.replace("LEGION_BANNER_PROTOCOL=tcp", f"LEGION_BANNER_PROTOCOL={protocol}")

    @staticmethod
    def _ensure_nmap_stats_every(command: str, interval: str = "15s") -> str:
        raw = str(command or "")
        stats_interval = str(interval or "15s").strip() or "15s"
        if "nmap" not in raw.lower():
            return raw

        separators = {"||", "&&", ";", "|", "(", ")", "\n"}
        parts = []
        start = 0
        index = 0
        quote = ""
        escaped = False

        while index < len(raw):
            char = raw[index]
            if escaped:
                escaped = False
                index += 1
                continue
            if char == "\\" and quote != "'":
                escaped = True
                index += 1
                continue
            if quote:
                if char == quote:
                    quote = ""
                index += 1
                continue
            if char in ("'", '"'):
                quote = char
                index += 1
                continue
            if raw.startswith("||", index) or raw.startswith("&&", index):
                parts.append(raw[start:index])
                parts.append(raw[index:index + 2])
                index += 2
                start = index
                continue
            if char in ";|()\n":
                parts.append(raw[start:index])
                parts.append(char)
                index += 1
                start = index
                continue
            index += 1
        parts.append(raw[start:])

        updated_parts = []
        nmap_prefix = re.compile(r"(?i)^(?:(?:sudo|doas|env|timeout|nice|ionice)\b[^\n;|&()]*?\s+)*nmap\b")
        has_stats = re.compile(r"(?i)(?:^|\s)--stats-every(?:=|\s)")
        has_verbose = re.compile(r"(?i)(?:^|\s)(?:-v{1,3}|--verbose)(?:\s|$)")

        for part in parts:
            if part in separators:
                updated_parts.append(part)
                continue
            stripped = part.strip()
            if not stripped or not nmap_prefix.match(stripped):
                updated_parts.append(part)
                continue
            leading = part[:len(part) - len(part.lstrip())]
            trailing = part[len(part.rstrip()):]
            normalized = stripped
            if not has_stats.search(normalized):
                normalized = f"{normalized} --stats-every {stats_interval}"
            if has_stats.search(normalized) and not has_verbose.search(normalized):
                normalized = f"{normalized} -vv"
            updated_parts.append(f"{leading}{normalized}{trailing}")

        return "".join(updated_parts)

    @staticmethod
    def _ensure_nmap_hostname_target_support(command: str, target_host: str) -> str:
        raw = str(command or "")
        hostname = normalize_hostname_alias(target_host)
        if "nmap" not in raw.lower() or not hostname:
            return raw
        normalized = re.sub(r"(?<!\S)-n(?!\S)", "", raw)
        normalized = re.sub(r"[ \t]{2,}", " ", normalized)
        normalized = re.sub(r"\(\s+", "(", normalized)
        normalized = re.sub(r"\s+\)", ")", normalized)
        return normalized.strip()

    @staticmethod
    def _ensure_nmap_vuln_command(command: str) -> str:
        raw = str(command or "").strip()
        if "nmap" not in raw.lower() or "--script" not in raw.lower():
            return raw
        if "vuln" not in raw.lower():
            return raw

        normalized = raw
        if "||" not in raw or "vulners" not in raw.lower():
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
                normalized = with_vulners
            else:
                normalized = f"({with_vulners} || {fallback})"

        return AppSettings._ensure_nmap_output_argument(normalized, "[OUTPUT]")

    @staticmethod
    def _ensure_nmap_output_argument(command: str, output_target: str) -> str:
        raw = str(command or "")
        output = str(output_target or "").strip()
        if "nmap" not in raw.lower() or not output:
            return raw

        separators = {"||", "&&", ";", "|", "(", ")", "\n"}
        parts = []
        start = 0
        index = 0
        quote = ""
        escaped = False

        while index < len(raw):
            char = raw[index]
            if escaped:
                escaped = False
                index += 1
                continue
            if char == "\\" and quote != "'":
                escaped = True
                index += 1
                continue
            if quote:
                if char == quote:
                    quote = ""
                index += 1
                continue
            if char in ("'", '"'):
                quote = char
                index += 1
                continue
            if raw.startswith("||", index) or raw.startswith("&&", index):
                parts.append(raw[start:index])
                parts.append(raw[index:index + 2])
                index += 2
                start = index
                continue
            if char in ";|()\n":
                parts.append(raw[start:index])
                parts.append(char)
                index += 1
                start = index
                continue
            index += 1
        parts.append(raw[start:])

        updated_parts = []
        nmap_prefix = re.compile(r"(?i)^(?:(?:sudo|doas|env|timeout|nice|ionice)\b[^\n;|&()]*?\s+)*nmap\b")
        has_output = re.compile(r"(?i)(?:^|\s)-oA(?:\s|$)")

        for part in parts:
            if part in separators:
                updated_parts.append(part)
                continue

            stripped = part.strip()
            if not stripped or has_output.search(stripped) or not nmap_prefix.match(stripped):
                updated_parts.append(part)
                continue

            leading = part[:len(part) - len(part.lstrip())]
            trailing = part[len(part.rstrip()):]
            updated_parts.append(f"{leading}{stripped} -oA {output}{trailing}")

        return "".join(updated_parts)

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
    def _wrap_command_presence_probe(cls, command: str, binary: str) -> str:
        raw = str(command or "")
        tool = str(binary or "").strip()
        if not raw.strip() or not tool:
            return raw
        probe_marker = f"__LEGION_{re.sub(r'[^A-Za-z0-9]+', '_', tool).upper()}_PROBE__"
        normalized = re.sub(
            rf"(?i)command\s+-v\s+{re.escape(tool)}",
            f"command -v {probe_marker}",
            raw,
        )
        normalized = re.sub(
            rf"(?is)^\s*\(\s*command\s+-v\s+{re.escape(probe_marker)}\s*>/dev/null\s+2>&1\s*&&\s*",
            "",
            normalized,
            count=1,
        )
        normalized = re.sub(
            rf"(?is)\)\s*\|\|\s*echo\s+{re.escape(tool)}\s+not\s+found\s*$",
            "",
            normalized,
            count=1,
        )
        normalized = normalized.strip()
        return f"if command -v {tool} >/dev/null 2>&1; then {normalized}; else echo {tool} not found; fi"

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

    @classmethod
    def _ensure_httpx_command(cls, command: str) -> str:
        raw = cls._canonicalize_web_target_placeholders(str(command or ""))
        if "httpx" not in raw.lower():
            return raw
        probe_marker = "__LEGION_HTTPX_PROBE__"
        normalized = re.sub(r"(?i)command\s+-v\s+httpx", f"command -v {probe_marker}", raw)
        wrapped_prefix = re.search(
            rf"(?i)^\s*\(\s*command\s+-v\s+{re.escape(probe_marker)}\s*>/dev/null\s+2>&1\s*&&\s*",
            normalized,
        )
        fallback = ""
        fallback_match = re.search(
            r"(?i)\s*\|\|\s*echo\s+httpx\s+not\s+found(?:\s+-o\s+\S+)?\s*$",
            normalized,
        )
        if fallback_match:
            fallback = " || echo httpx not found"
            normalized = normalized[:fallback_match.start()]
        if wrapped_prefix:
            normalized = normalized[wrapped_prefix.end():]
            normalized = re.sub(r"\)\s*$", "", normalized)
            prefix = f"(command -v {probe_marker} >/dev/null 2>&1 && "
        else:
            prefix = ""
        httpx_match = re.search(r"(?i)\bhttpx\b", normalized)
        if not httpx_match:
            return re.sub(r"\s{2,}", " ", raw).strip()
        if not wrapped_prefix:
            prefix = normalized[: httpx_match.start()]
        httpx_command = normalized[httpx_match.start() :]
        httpx_command = re.sub(r"(?i)(?:^|\s)-(?:j|json)(?=\s|$)", " ", httpx_command)
        httpx_command = re.sub(r"(?i)(?:^|\s)-silent(?=\s|$)", " ", httpx_command)
        httpx_command = re.sub(r"(?i)(?:^|\s)-title(?=\s|$)", " ", httpx_command)
        httpx_command = re.sub(r"(?i)(?:^|\s)-tech-detect(?=\s|$)", " ", httpx_command)
        httpx_command = re.sub(r"(?i)(?:^|\s)-(?:web-server|server)(?=\s|$)", " ", httpx_command)
        httpx_command = re.sub(r"(?i)(?:^|\s)-status-code(?=\s|$)", " ", httpx_command)
        httpx_command = re.sub(r"(?i)(?:^|\s)-content-type(?=\s|$)", " ", httpx_command)
        httpx_command = re.sub(r"(?i)(?:^|\s)-o\s+\S+", " ", httpx_command)
        httpx_command = re.sub(r"\s*>\s*\[OUTPUT\][^\s\)]*", " ", httpx_command)
        if not re.search(r"(?i)(?:^|\s)-(?:u|target)(?:\s|$)", httpx_command):
            httpx_command = re.sub(r"(?i)\bhttpx\b", "httpx -u [WEB_URL]", httpx_command, count=1)
        else:
            httpx_command = re.sub(r"(?i)(?:^|\s)-(?:u|target)\s+\S+", " -u [WEB_URL]", httpx_command, count=1)
        httpx_command = re.sub(
            r"(?i)\bhttpx\b",
            "httpx -silent -json -title -tech-detect -web-server -status-code -content-type",
            httpx_command,
            count=1,
        )
        if not re.search(r"(?i)(?:^|\s)-o(?:\s|$)", httpx_command):
            httpx_command += " -o [OUTPUT].jsonl"
        if wrapped_prefix:
            combined = f"{prefix}{httpx_command}){fallback or ' || echo httpx not found'}"
        else:
            combined = f"{prefix}{httpx_command}{fallback}"
        return re.sub(r"\s{2,}", " ", combined).strip().replace(probe_marker, "httpx")

    @classmethod
    def _ensure_subfinder_command(cls, command: str) -> str:
        raw = str(command or "")
        if "subfinder" not in raw.lower():
            return raw
        probe_marker = "__LEGION_SUBFINDER_PROBE__"
        normalized = re.sub(
            r"(?i)command\s+-v\s+subfinder(?:\s+\S+)*?\s*>/dev/null\s+2>&1",
            f"command -v {probe_marker} >/dev/null 2>&1",
            raw,
        )
        wrapped_prefix = re.search(
            rf"(?i)^\s*\(\s*command\s+-v\s+{re.escape(probe_marker)}\s*>/dev/null\s+2>&1\s*&&\s*",
            normalized,
        )
        fallback = ""
        fallback_match = re.search(
            r"(?i)\s*\|\|\s*echo\s+subfinder\s+not\s+found(?:\s+-o\s+\S+)?\s*$",
            normalized,
        )
        if fallback_match:
            fallback = " || echo subfinder not found"
            normalized = normalized[:fallback_match.start()]
        if wrapped_prefix:
            normalized = normalized[wrapped_prefix.end():]
            normalized = re.sub(r"\)\s*$", "", normalized)
            prefix = f"(command -v {probe_marker} >/dev/null 2>&1 && "
        else:
            prefix = ""

        subfinder_match = re.search(r"(?i)\bsubfinder\b", normalized)
        if not subfinder_match:
            return re.sub(r"\s{2,}", " ", raw).strip()
        if not wrapped_prefix:
            prefix = normalized[: subfinder_match.start()]
        subfinder_command = normalized[subfinder_match.start():]
        subfinder_command = re.sub(r"(?i)(?:^|\s)-d(?:omain)?\s+\S+", " -d [IP]", subfinder_command)
        subfinder_command = re.sub(r"(?i)(?:^|\s)-dL\s+\S+", " ", subfinder_command)
        subfinder_command = re.sub(r"(?i)(?:^|\s)-o\s+\S+", " ", subfinder_command)
        subfinder_command = re.sub(r"(?i)(?:^|\s)-max-time\s+\S+", " ", subfinder_command)
        subfinder_command = re.sub(r"(?i)(?:^|\s)-oJ\b", " ", subfinder_command)
        subfinder_command = re.sub(r"(?i)(?:^|\s)-silent\b", " ", subfinder_command)
        subfinder_command = re.sub(r"(?i)(?:^|\s)-recursive\b", " ", subfinder_command)
        subfinder_command = re.sub(r"(?i)(?:^|\s)-duc\b", " ", subfinder_command)
        if not re.search(r"(?i)(?:^|\s)-d(?:omain)?(?:\s|$)", subfinder_command):
            subfinder_command = re.sub(r"(?i)\bsubfinder\b", "subfinder -d [IP]", subfinder_command, count=1)
        subfinder_command = re.sub(
            r"(?i)\bsubfinder\b",
            "subfinder -silent -recursive -duc -max-time 5 -oJ",
            subfinder_command,
            count=1,
        )
        if not re.search(r"(?i)(?:^|\s)-o(?:\s|$)", subfinder_command):
            subfinder_command += " -o [OUTPUT].jsonl"
        if wrapped_prefix:
            combined = f"{prefix}{subfinder_command}){fallback or ' || echo subfinder not found'}"
        else:
            combined = f"{prefix}{subfinder_command}{fallback}"
        return re.sub(r"\s{2,}", " ", combined).strip().replace(probe_marker, "subfinder")

    @classmethod
    def _ensure_katana_command(cls, command: str) -> str:
        raw = cls._canonicalize_web_target_placeholders(str(command or ""))
        if "katana" not in raw.lower():
            return raw
        probe_marker = "__LEGION_KATANA_PROBE__"
        normalized = re.sub(r"(?i)command\s+-v\s+katana", f"command -v {probe_marker}", raw)
        normalized = re.sub(r"(?i)(?:^|\s)-jsonl\b", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)-silent\b", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)-jc\b", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)-kf\s+\S+", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)-d\s+\S+", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)-c\s+\S+", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)-p\s+\S+", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)-rl\s+\S+", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)-o\s+\S+", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)-u\s+\S+", " -u [WEB_URL]", normalized, count=1)
        if not re.search(r"(?i)(?:^|\s)-u(?:\s|$)", normalized):
            normalized = re.sub(r"(?i)\bkatana\b", "katana -u [WEB_URL]", normalized, count=1)
        normalized = re.sub(
            r"(?i)\bkatana\b",
            "katana -silent -jsonl -d 2 -jc -kf robotstxt,sitemapxml -c 5 -p 1 -rl 5",
            normalized,
            count=1,
        )
        if not re.search(r"(?i)(?:^|\s)-o(?:\s|$)", normalized):
            normalized += " -o [OUTPUT].jsonl"
        normalized = re.sub(r"\s{2,}", " ", normalized).strip()
        return normalized.replace(probe_marker, "katana")

    @classmethod
    def _ensure_whatweb_command(cls, command: str) -> str:
        raw = str(command or "")
        if "whatweb" not in raw.lower():
            return raw
        normalized = cls._canonicalize_web_target_placeholders(raw)
        normalized = re.sub(r"(?i)\s+--color(?:=|\s+)always\b", " --color=never", normalized)
        if "--color=never" not in normalized.lower():
            normalized = re.sub(r"(?i)\bwhatweb\b", "whatweb --color=never", normalized, count=1)
        if not re.search(r"(?i)--log-brief(?:=|\s)", normalized):
            normalized = re.sub(r"(?i)\bwhatweb\b", "whatweb --log-brief=[OUTPUT].txt", normalized, count=1)
            normalized = re.sub(
                r"(?i)\bwhatweb\s+--log-brief=\[OUTPUT\]\.txt\b",
                "whatweb --color=never --log-brief=[OUTPUT].txt",
                normalized,
                count=1,
            )
        return re.sub(r"\s{2,}", " ", normalized).strip()

    @classmethod
    def _ensure_nikto_command(cls, command: str) -> str:
        raw = cls._canonicalize_web_target_placeholders(str(command or ""))
        if "nikto" not in raw.lower():
            return raw
        probe_marker = "__LEGION_NIKTO_PROBE__"
        normalized = re.sub(r"(?i)command\s+-v\s+nikto", f"command -v {probe_marker}", raw)
        normalized = re.sub(r"(?i)(?:^|\s)-p(?:ort)?\s+\[PORT\](?=\s|$)", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)-(?:h|host)\s+\S+", " -h [WEB_URL]", normalized, count=1)
        normalized = re.sub(r"(?i)(?:^|\s)-(?:o|output)\s+\S+", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)-format\s+\S+", " ", normalized)
        if "-h [WEB_URL]" not in normalized:
            normalized = re.sub(r"(?i)\bnikto\b", "nikto -h [WEB_URL]", normalized, count=1)
        normalized = re.sub(r"(?i)\bnikto\b", "nikto -nointeractive -Format txt -output [OUTPUT].txt", normalized, count=1)
        return re.sub(r"\s{2,}", " ", normalized).strip().replace(probe_marker, "nikto")

    @classmethod
    def _ensure_wpscan_command(cls, command: str) -> str:
        raw = cls._canonicalize_web_target_placeholders(str(command or ""))
        if "wpscan" not in raw.lower():
            return raw
        probe_marker = "__LEGION_WPSCAN_PROBE__"
        normalized = re.sub(r"(?i)command\s+-v\s+wpscan", f"command -v {probe_marker}", raw)
        normalized = re.sub(r"(?i)(?:^|\s)--url\s+\S+", " --url [WEB_URL]", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)--(?:no-)?update(?=\s|$)", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)--disable-tls-checks(?=\s|$)", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)--format\s+\S+", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)(?:-o|--output)\s+\S+", " ", normalized)
        if "--url [WEB_URL]" not in normalized:
            normalized = re.sub(r"(?i)\bwpscan\b", "wpscan --url [WEB_URL]", normalized)
        normalized = re.sub(
            r"(?i)\bwpscan\b",
            "wpscan --disable-tls-checks --no-update --format json --output [OUTPUT].json",
            normalized,
        )
        return re.sub(r"\s{2,}", " ", normalized).strip().replace(probe_marker, "wpscan")

    @classmethod
    def _ensure_dirsearch_command(cls, command: str) -> str:
        raw = cls._canonicalize_web_target_placeholders(str(command or ""))
        if "dirsearch" not in raw.lower():
            return raw
        probe_marker = "__LEGION_DIRSEARCH_PROBE__"
        normalized = re.sub(r"(?i)command\s+-v\s+dirsearch", f"command -v {probe_marker}", raw)
        normalized = re.sub(r"\[WEB_URL\](?!/)", "[WEB_URL]/", normalized)
        if "--quiet-mode" not in normalized.lower():
            normalized = re.sub(r"(?i)\bdirsearch\b", "dirsearch --quiet-mode", normalized, count=1)
        if "--format=json" not in normalized.lower():
            normalized += " --format=json"
        if not re.search(r"(?i)--output(?:=|\s)", normalized):
            normalized += " --output=[OUTPUT].json"
        return re.sub(r"\s{2,}", " ", normalized).strip().replace(probe_marker, "dirsearch")

    @classmethod
    def _ensure_ffuf_command(cls, command: str) -> str:
        raw = cls._canonicalize_web_target_placeholders(str(command or ""))
        if "ffuf" not in raw.lower():
            return raw
        probe_marker = "__LEGION_FFUF_PROBE__"
        normalized = re.sub(r"(?i)command\s+-v\s+ffuf", f"command -v {probe_marker}", raw)
        normalized = re.sub(r"\[WEB_URL\](?:/FUZZ|/)?", "[WEB_URL]/FUZZ", normalized, count=1)
        normalized = re.sub(r"(?i)(?:^|\s)-json(?=\s|$)", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)-noninteractive(?=\s|$)", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)-s(?=\s|$)", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)-of\s+\S+", " ", normalized)
        normalized = re.sub(r"(?i)(?:^|\s)-o\s+\S+", " ", normalized)
        normalized = re.sub(r"\s*>\s*\[OUTPUT\][^\s\)]*", " ", normalized)
        normalized = re.sub(r"(?i)\bffuf\b", "ffuf -s -of json -o [OUTPUT].json", normalized, count=1)
        return re.sub(r"\s{2,}", " ", normalized).strip().replace(probe_marker, "ffuf")

    @staticmethod
    def _ensure_hydra_command(command: str) -> str:
        raw = str(command or "")
        if "hydra" not in raw.lower():
            return raw
        normalized = re.sub(r"(?i)-o\s+(?:\\?\"|')([^\"']+)(?:\\?\"|')", r"-o \1", raw)
        normalized = re.sub(r"(?i)-o\s+\[OUTPUT\](?!\.)", "-o [OUTPUT].txt", normalized)
        return re.sub(r"\s{2,}", " ", normalized).strip()

    @staticmethod
    def _ensure_enum4linux_ng_command(command: str) -> str:
        raw = str(command or "")
        if "enum4linux-ng" not in raw.lower():
            return raw
        return AppSettings.ENUM4LINUX_NG_COMMAND

    @staticmethod
    def _ensure_smbmap_command(command: str) -> str:
        raw = str(command or "")
        if "smbmap" not in raw.lower():
            return raw
        return AppSettings.SMBMAP_COMMAND

    @staticmethod
    def _ensure_rpcclient_enum_command(command: str) -> str:
        raw = str(command or "")
        if "rpcclient" not in raw.lower():
            return raw
        return AppSettings.RPCCLIENT_ENUM_COMMAND

    @staticmethod
    def _ensure_netexec_command(command: str) -> str:
        raw = str(command or "")
        lowered = raw.lower()
        if "netexec" not in lowered and "nxc" not in lowered and "crackmapexec" not in lowered:
            return raw
        return AppSettings.NETEXEC_COMMAND

    @staticmethod
    def _ensure_responder_command(command: str) -> str:
        raw = str(command or "")
        if "responder" not in raw.lower():
            return raw
        return AppSettings.RESPONDER_COMMAND

    @staticmethod
    def _ensure_ntlmrelayx_command(command: str) -> str:
        raw = str(command or "")
        lowered = raw.lower()
        if "ntlmrelayx" not in lowered and "impacket-ntlmrelayx" not in lowered:
            return raw
        return AppSettings.NTLMRELAYX_COMMAND

    @staticmethod
    def _canonicalize_legacy_rpcclient_action(rpc_command: str) -> str:
        token = str(rpc_command or "").strip() or "srvinfo"
        return f"rpcclient [IP] -U '%' -c '{token}'"

    @staticmethod
    def _canonicalize_legacy_net_rpc_group_members_action(group_name: str) -> str:
        token = str(group_name or "").strip() or "Domain Admins"
        safe_token = token.replace("'", "'\"'\"'")
        return f"net rpc group members '{safe_token}' -I [IP] -U '%'"

    @staticmethod
    def _canonicalize_legacy_snmp_brute_action() -> str:
        return "medusa -h [IP] -u root -P ./wordlists/snmp-default.txt -M snmp | grep SUCCESS"

    @staticmethod
    def _ensure_terminal_rpcclient_command(command: str) -> str:
        raw = str(command or "")
        if "rpcclient" not in raw.lower():
            return raw
        prefix = "[term] " if "[term]" in raw.lower() else ""
        return f"{prefix}rpcclient [IP] -p [PORT] -U '%'"

    @staticmethod
    def _canonicalize_web_target_placeholders(command: str) -> str:
        normalized = str(command or "")
        replacements = (
            ("https://[IP]:[PORT]", "[WEB_URL]"),
            ("http://[IP]:[PORT]", "[WEB_URL]"),
            ("https://[IP]", "[WEB_URL]"),
            ("http://[IP]", "[WEB_URL]"),
        )
        for old, new in replacements:
            normalized = normalized.replace(old, new)
        return normalized

    @staticmethod
    def _collapse_redundant_fallbacks(command: str) -> str:
        normalized = str(command or "")
        duplicate_or_pattern = re.compile(r"\(\s*([^()]+?)\s*\|\|\s*([^()]+?)\s*\)")

        while True:
            changed = False

            def _replace(match):
                nonlocal changed
                left = re.sub(r"\s+", " ", str(match.group(1) or "")).strip()
                right = re.sub(r"\s+", " ", str(match.group(2) or "")).strip()
                if left == right and left:
                    changed = True
                    return f"({left})"
                return match.group(0)

            updated = duplicate_or_pattern.sub(_replace, normalized)
            if not changed:
                return updated
            normalized = updated

    @classmethod
    def allowed_nonzero_exit_codes(cls, tool_id: str):
        normalized_tool = str(tool_id or "").strip().lower()
        return {int(value) for value in cls.ALLOWED_NONZERO_EXIT_CODES.get(normalized_tool, set())}

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
            value = self.actions.value(k)
            label = value[0]
            command = self._normalize_action_command(str(k), value[1])
            hostactions.append([label, str(k), command])
            sortArray.append(label)
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
            if str(k or "").strip().lower() in self.DISABLED_PORT_ACTION_IDS:
                continue
            value = self.actions.value(k)
            label = value[0]
            command = self._normalize_action_command(str(k), value[1])
            scope = value[2]
            portactions.append([label, str(k), command, scope])
            sortArray.append(label)
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
            value = self.actions.value(k)
            label = value[0]
            command = self._normalize_action_command(str(k), value[1])
            scope = value[2]
            portactions.append([label, str(k), command, scope])
            sortArray.append(label)
        self.actions.endGroup()
        sortArrayWithArray(sortArray, portactions)  # sort by label so that it appears nicely in the context menu
        return portactions

    # this function fetches all the port actions that will be run as terminal commands from the settings file
    def getSchedulerSettings(self):
        settings = []
        self.actions.beginGroup('SchedulerSettings')
        keys = self.actions.childKeys()
        for k in keys:
            if str(k or "").strip().lower() in self.DISABLED_PORT_ACTION_IDS:
                continue
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

        self.actions = IniSettingsStore(conf_path)

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
