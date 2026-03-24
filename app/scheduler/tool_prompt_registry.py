from dataclasses import dataclass
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from app.tooling import list_legion_tool_specs


@dataclass(frozen=True)
class SchedulerToolPromptInfo:
    tool_id: str
    purpose: str
    when_to_use: str
    arg_shape: str = ""
    phase_tags: Tuple[str, ...] = ()
    prompt_groups: Tuple[str, ...] = ()
    safe_parallel: bool = False


_TOOL_PROMPT_ENTRIES: Tuple[SchedulerToolPromptInfo, ...] = (
    SchedulerToolPromptInfo(
        tool_id="nuclei-web",
        purpose="Broad web validation and exposure coverage.",
        when_to_use="Use when a live HTTP service still lacks broad automated baseline coverage.",
        arg_shape="web_url",
        phase_tags=("service_fingerprint", "broad_vuln"),
        prompt_groups=("web_baseline",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="nmap-vuln.nse",
        purpose="Known-service vulnerability checks on a specific port.",
        when_to_use="Use to close missing Nmap vuln coverage after service fingerprinting confirms a live target.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "broad_vuln", "protocol_checks"),
        prompt_groups=("web_baseline",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="screenshooter",
        purpose="Visual confirmation of the exposed service or application.",
        when_to_use="Use when screenshot coverage is still missing or when UI context matters.",
        arg_shape="web_url",
        phase_tags=("service_fingerprint", "deep_web"),
        prompt_groups=("web_baseline",),
        safe_parallel=True,
    ),
    SchedulerToolPromptInfo(
        tool_id="whatweb",
        purpose="Technology fingerprinting and stack hints.",
        when_to_use="Use for bounded stack validation after basic connectivity and headers are known.",
        arg_shape="web_url",
        phase_tags=("protocol_checks", "targeted_checks", "deep_web"),
        prompt_groups=("web_deep", "web_specialist_followup"),
        safe_parallel=True,
    ),
    SchedulerToolPromptInfo(
        tool_id="whatweb-http",
        purpose="HTTP-only technology fingerprinting and stack hints.",
        when_to_use="Use when the target is a clear HTTP endpoint and follow-up fingerprinting is still missing.",
        arg_shape="web_url",
        phase_tags=("protocol_checks", "targeted_checks", "deep_web"),
        prompt_groups=("web_deep", "web_specialist_followup"),
        safe_parallel=True,
    ),
    SchedulerToolPromptInfo(
        tool_id="whatweb-https",
        purpose="HTTPS technology fingerprinting and stack hints.",
        when_to_use="Use when TLS is present and follow-up fingerprinting is still missing.",
        arg_shape="web_url",
        phase_tags=("protocol_checks", "targeted_checks", "deep_web"),
        prompt_groups=("web_deep", "web_specialist_followup"),
        safe_parallel=True,
    ),
    SchedulerToolPromptInfo(
        tool_id="httpx",
        purpose="Lightweight web probing for titles, tech, server, and status.",
        when_to_use="Use for safe bounded confirmation of web behavior across a known live endpoint.",
        arg_shape="web_url",
        phase_tags=("protocol_checks", "targeted_checks", "deep_web"),
        prompt_groups=("web_deep", "web_specialist_followup"),
        safe_parallel=True,
    ),
    SchedulerToolPromptInfo(
        tool_id="subfinder",
        purpose="Passive external subdomain discovery against a host or domain root.",
        when_to_use="Use when an external hostname is in scope and passive subdomain expansion is justified before deeper follow-up.",
        arg_shape="host",
        phase_tags=("initial_discovery",),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="chaos",
        purpose="Passive external subdomain discovery from ProjectDiscovery Chaos against a root domain.",
        when_to_use="Use when an external hostname is in scope, a Chaos API key is configured, and passive root-domain expansion is justified before deeper follow-up.",
        arg_shape="host",
        phase_tags=("initial_discovery",),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="grayhatwarfare",
        purpose="Search Grayhat Warfare for public bucket or file exposure related to a root domain.",
        when_to_use="Use when an external hostname is in scope, a Grayhat Warfare API key is configured, and root-domain storage exposure enrichment is justified.",
        arg_shape="host",
        phase_tags=("initial_discovery",),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="shodan-enrichment",
        purpose="Search Shodan for hostname or certificate-indexed exposure related to an external hostname.",
        when_to_use="Use when an external domain or subdomain is in scope, a Shodan API key is configured, and passive external enrichment is justified.",
        arg_shape="host",
        phase_tags=("initial_discovery", "external_enrichment"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="nikto",
        purpose="Broad HTTP validation and known issue checks.",
        when_to_use="Use after basic fingerprinting when deeper web validation is still missing.",
        arg_shape="web_url",
        phase_tags=("targeted_checks", "deep_web"),
        prompt_groups=("web_deep", "web_specialist_followup"),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="web-content-discovery",
        purpose="Governed content discovery against a known web service.",
        when_to_use="Use when path coverage is still missing and broad rediscovery is justified.",
        arg_shape="web_url",
        phase_tags=("targeted_checks", "deep_web"),
        prompt_groups=("web_deep", "web_specialist_followup"),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="katana",
        purpose="Bounded web crawling and endpoint discovery with ProjectDiscovery Katana.",
        when_to_use="Use when a live web service needs deeper bounded crawl coverage after basic fingerprinting or content discovery.",
        arg_shape="web_url",
        phase_tags=("targeted_checks", "deep_web"),
        prompt_groups=("web_deep", "web_specialist_followup"),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="dirsearch",
        purpose="Directory and path discovery against a known web service.",
        when_to_use="Use for targeted path discovery when content coverage is still missing.",
        arg_shape="web_url",
        phase_tags=("targeted_checks", "deep_web"),
        prompt_groups=("web_deep", "web_specialist_followup"),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="ffuf",
        purpose="Content fuzzing against a known web path or root.",
        when_to_use="Use for bounded path discovery when a web service is confirmed and content coverage is missing.",
        arg_shape="web_url",
        phase_tags=("targeted_checks", "deep_web"),
        prompt_groups=("web_deep", "web_specialist_followup"),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="feroxbuster",
        purpose="Web content discovery fallback for real path enumeration.",
        when_to_use="Use when the governed content-discovery family is selected and Feroxbuster is the available backend.",
        arg_shape="web_url",
        phase_tags=("targeted_checks", "deep_web"),
        prompt_groups=("web_specialist_followup",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="gobuster",
        purpose="Legacy web content discovery fallback.",
        when_to_use="Use when the governed content-discovery family is selected and Gobuster is the available backend.",
        arg_shape="web_url",
        phase_tags=("targeted_checks", "deep_web"),
        prompt_groups=("web_specialist_followup",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="nuclei-cves",
        purpose="CVE-focused nuclei follow-up against a known web stack.",
        when_to_use="Use when a technology or version hint justifies targeted CVE validation.",
        arg_shape="web_url",
        phase_tags=("protocol_checks", "targeted_checks", "deep_web"),
        prompt_groups=("web_targeted_nuclei", "web_specialist_followup"),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="nuclei-exposures",
        purpose="Exposure-focused nuclei follow-up against a known web stack.",
        when_to_use="Use when configuration exposure or known panel exposure is plausible.",
        arg_shape="web_url",
        phase_tags=("protocol_checks", "targeted_checks", "deep_web"),
        prompt_groups=("web_targeted_nuclei", "web_specialist_followup"),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="nuclei-wordpress",
        purpose="WordPress-specific nuclei follow-up.",
        when_to_use="Use only when there is concrete WordPress evidence on the target.",
        arg_shape="web_url",
        phase_tags=("targeted_checks", "deep_web"),
        prompt_groups=("web_targeted_nuclei", "web_specialist_followup"),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="curl-headers",
        purpose="Read-only header capture and redirect confirmation.",
        when_to_use="Use for bounded HTTP/TLS metadata checks without broad scanning.",
        arg_shape="web_url",
        phase_tags=("protocol_checks", "targeted_checks", "deep_web"),
        prompt_groups=("web_http_followup", "web_specialist_followup"),
        safe_parallel=True,
    ),
    SchedulerToolPromptInfo(
        tool_id="curl-options",
        purpose="Read-only HTTP method and OPTIONS validation.",
        when_to_use="Use to confirm allowed methods when HTTP follow-up coverage is still missing.",
        arg_shape="web_url",
        phase_tags=("protocol_checks", "targeted_checks", "deep_web"),
        prompt_groups=("web_http_followup", "web_specialist_followup"),
        safe_parallel=True,
    ),
    SchedulerToolPromptInfo(
        tool_id="curl-robots",
        purpose="Read-only robots.txt and sitemap hints.",
        when_to_use="Use for bounded path hints without invoking broader content discovery.",
        arg_shape="web_url",
        phase_tags=("protocol_checks", "targeted_checks", "deep_web"),
        prompt_groups=("web_http_followup", "web_specialist_followup"),
        safe_parallel=True,
    ),
    SchedulerToolPromptInfo(
        tool_id="http-title",
        purpose="Capture the HTTP page title and lightweight response identity hints.",
        when_to_use="Use for fast passive confirmation of what an HTTP endpoint presents before broader follow-up.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "protocol_checks"),
        prompt_groups=(),
        safe_parallel=True,
    ),
    SchedulerToolPromptInfo(
        tool_id="http-server-header",
        purpose="Capture the HTTP Server header and related response metadata.",
        when_to_use="Use for passive header validation when stack or proxy clues are still missing.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "protocol_checks"),
        prompt_groups=(),
        safe_parallel=True,
    ),
    SchedulerToolPromptInfo(
        tool_id="http-server-header.nse",
        purpose="Capture the HTTP Server header and related response metadata with Nmap NSE.",
        when_to_use="Use for passive header validation when stack or proxy clues are still missing.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "protocol_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="http-waf-detect.nse",
        purpose="Detect WAF or reverse-proxy behavior on an HTTP endpoint with Nmap NSE.",
        when_to_use="Use when a live web service may be fronted by protection layers and that behavior still needs confirmation.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "protocol_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="wafw00f",
        purpose="WAF detection and protection fingerprinting.",
        when_to_use="Use when a web service is live and WAF/protection behavior needs confirmation.",
        arg_shape="web_url",
        phase_tags=("service_fingerprint", "protocol_checks", "targeted_checks"),
        prompt_groups=("web_specialist_followup",),
        safe_parallel=True,
    ),
    SchedulerToolPromptInfo(
        tool_id="sslscan",
        purpose="TLS protocol, cipher, and certificate posture validation.",
        when_to_use="Use when TLS is present and posture or weak protocol coverage is still missing.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "protocol_checks", "targeted_checks"),
        prompt_groups=("web_specialist_followup",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="testssl.sh",
        purpose="TLS protocol, certificate, and cipher validation using testssl.sh.",
        when_to_use="Use when TLS is present and deeper certificate or protocol posture validation is needed.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "protocol_checks", "targeted_checks"),
        prompt_groups=("web_specialist_followup",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="nuclei-cloud",
        purpose="Cloud and storage exposure follow-up with nuclei templates.",
        when_to_use="Use when an external web hostname is in scope and cloud-backed exposure validation is justified.",
        arg_shape="web_url",
        phase_tags=("protocol_checks", "targeted_checks", "external_enrichment"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="nuclei-aws-storage",
        purpose="AWS and S3 storage exposure follow-up with nuclei templates.",
        when_to_use="Use after cloud fingerprinting when there is concrete AWS or S3 storage evidence to validate.",
        arg_shape="web_url",
        phase_tags=("targeted_checks", "external_enrichment"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="nuclei-azure-storage",
        purpose="Azure Blob and storage exposure follow-up with nuclei templates.",
        when_to_use="Use after cloud fingerprinting when there is concrete Azure storage evidence to validate.",
        arg_shape="web_url",
        phase_tags=("targeted_checks", "external_enrichment"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="nuclei-gcp-storage",
        purpose="GCP and GCS storage exposure follow-up with nuclei templates.",
        when_to_use="Use after cloud fingerprinting when there is concrete Google Cloud Storage evidence to validate.",
        arg_shape="web_url",
        phase_tags=("targeted_checks", "external_enrichment"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="nuclei-aws-rds",
        purpose="AWS RDS managed database exposure follow-up with nuclei templates.",
        when_to_use="Use after cloud fingerprinting when there is concrete Amazon RDS evidence on a reachable database endpoint.",
        arg_shape="host:port",
        phase_tags=("targeted_checks", "external_enrichment"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="nuclei-aws-aurora",
        purpose="AWS Aurora managed database exposure follow-up with nuclei templates.",
        when_to_use="Use after cloud fingerprinting when there is concrete Amazon Aurora evidence on a reachable database endpoint.",
        arg_shape="host:port",
        phase_tags=("targeted_checks", "external_enrichment"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="nuclei-azure-cosmos",
        purpose="Azure Cosmos DB exposure follow-up with nuclei templates.",
        when_to_use="Use after cloud fingerprinting when there is concrete Azure Cosmos DB evidence on a reachable web or API endpoint.",
        arg_shape="web_url",
        phase_tags=("targeted_checks", "external_enrichment"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="nuclei-gcp-cloudsql",
        purpose="Google Cloud SQL managed database exposure follow-up with nuclei templates.",
        when_to_use="Use after cloud fingerprinting when there is concrete Google Cloud SQL evidence on a reachable database endpoint.",
        arg_shape="host:port",
        phase_tags=("targeted_checks", "external_enrichment"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="wpscan",
        purpose="WordPress-specific enumeration and follow-up.",
        when_to_use="Use only when there is concrete WordPress evidence and a WordPress follow-up gap remains.",
        arg_shape="web_url",
        phase_tags=("targeted_checks", "deep_web"),
        prompt_groups=("web_specialist_followup",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="http-errors.nse",
        purpose="Probe HTTP error handling and response behavior with Nmap NSE.",
        when_to_use="Use when passive HTTP fingerprinting is complete and error-page behavior may reveal stack clues or misconfigurations.",
        arg_shape="host:port",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="http-auth-finder.nse",
        purpose="Identify HTTP authentication-protected paths and challenge behavior with Nmap NSE.",
        when_to_use="Use when a web service is live and the protected auth surface still needs bounded discovery.",
        arg_shape="host:port",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="http-auth.nse",
        purpose="Enumerate supported HTTP authentication schemes and challenge responses with Nmap NSE.",
        when_to_use="Use when an HTTP service may expose auth prompts and authentication posture still needs validation.",
        arg_shape="host:port",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="http-open-redirect.nse",
        purpose="Check for open-redirect behavior on an HTTP endpoint with Nmap NSE.",
        when_to_use="Use when a live web service still needs bounded redirect validation without broader application fuzzing.",
        arg_shape="host:port",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="http-ntlm-info.nse",
        purpose="Collect NTLM challenge details and Windows auth hints from HTTP responses with Nmap NSE.",
        when_to_use="Use when a Windows-backed HTTP service may expose NTLM authentication metadata or domain/workstation clues.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "protocol_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="http-git.nse",
        purpose="Check for exposed Git metadata or repositories over HTTP with Nmap NSE.",
        when_to_use="Use when content discovery or direct HTTP probing suggests an exposed repository or leftover developer artifacts.",
        arg_shape="host:port",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="http-passwd.nse",
        purpose="Check for exposed passwd-style files or traversal leaks over HTTP with Nmap NSE.",
        when_to_use="Use when HTTP path handling looks unusual and a bounded file exposure check is justified.",
        arg_shape="host:port",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="http-google-malware.nse",
        purpose="Check Google Safe Browsing-style malware reputation for a public HTTP endpoint with Nmap NSE.",
        when_to_use="Use only when external reputation validation is relevant for a reachable web target.",
        arg_shape="host:port",
        phase_tags=("targeted_checks",),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="http-frontpage-login.nse",
        purpose="Check for legacy FrontPage login endpoints over HTTP with Nmap NSE.",
        when_to_use="Use only when legacy Microsoft web administration surfaces are plausible on the target.",
        arg_shape="host:port",
        phase_tags=("targeted_checks",),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="http-apache-negotiation.nse",
        purpose="Check for Apache content-negotiation behavior over HTTP with Nmap NSE.",
        when_to_use="Use only when Apache-style negotiation behavior is plausible or remaining passive HTTP checks are limited.",
        arg_shape="host:port",
        phase_tags=("protocol_checks",),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="membase-http-info.nse",
        purpose="Probe Membase or Couchbase-style HTTP management information with Nmap NSE.",
        when_to_use="Use only when the web surface suggests a Membase or Couchbase management endpoint.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="riak-http-info.nse",
        purpose="Probe Riak HTTP interface details and version hints with Nmap NSE.",
        when_to_use="Use only when the web surface suggests a Riak endpoint or related management interface.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="banner",
        purpose="Quick banner and basic service proofing.",
        when_to_use="Use when lightweight service confirmation is still missing.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "protocol_checks"),
        prompt_groups=(),
        safe_parallel=True,
    ),
    SchedulerToolPromptInfo(
        tool_id="enum4linux-ng",
        purpose="Safer SMB and AD-aware internal enumeration.",
        when_to_use="Use when safe internal enumeration is missing on an SMB target.",
        arg_shape="host",
        phase_tags=("service_fingerprint", "protocol_checks", "targeted_checks"),
        prompt_groups=("internal_safe_enum",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="smbmap",
        purpose="SMB share and access enumeration.",
        when_to_use="Use when SMB share visibility matters and safe internal enumeration is missing.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "protocol_checks", "targeted_checks"),
        prompt_groups=("internal_safe_enum",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="rpcclient-enum",
        purpose="Null-session and RPC-based SMB enumeration.",
        when_to_use="Use when SMB/RPC enumeration is justified and safe internal enum coverage is missing.",
        arg_shape="host",
        phase_tags=("service_fingerprint", "protocol_checks", "targeted_checks"),
        prompt_groups=("internal_safe_enum",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="enum4linux",
        purpose="Legacy SMB and AD enumeration fallback.",
        when_to_use="Use when SMB follow-up is still needed and enum4linux-ng is unavailable or inconclusive.",
        arg_shape="host",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=("internal_safe_enum",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="smbenum",
        purpose="Legacy SMB wrapper for shares, users, and policy hints.",
        when_to_use="Use when bounded SMB follow-up is still needed and the local wrapper is available.",
        arg_shape="host",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=("internal_safe_enum",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="smb-null-sessions",
        purpose="Null-session viability check over SMB/RPC.",
        when_to_use="Use to confirm anonymous SMB posture before deeper RPC or identity checks.",
        arg_shape="host",
        phase_tags=("service_fingerprint", "protocol_checks"),
        prompt_groups=("internal_safe_enum",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="smb-enum-admins",
        purpose="Enumerate Domain Admins membership over SMB/Net RPC.",
        when_to_use="Use only after basic SMB reachability is confirmed and identity posture follow-up is justified.",
        arg_shape="host",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="smb-enum-groups",
        purpose="Enumerate SMB and domain groups with Nmap NSE.",
        when_to_use="Use when group enumeration is still missing after initial SMB connectivity checks.",
        arg_shape="host:port",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="smb-enum-sessions",
        purpose="Enumerate SMB sessions and logged-on user hints with Nmap NSE.",
        when_to_use="Use when session posture matters and SMB follow-up remains justified.",
        arg_shape="host:port",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="smb-enum-shares",
        purpose="Enumerate SMB shares with Nmap NSE.",
        when_to_use="Use when safe share visibility is still missing on a reachable SMB service.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "protocol_checks", "targeted_checks"),
        prompt_groups=("internal_safe_enum",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="smb-enum-users",
        purpose="Enumerate SMB and domain user accounts with Nmap NSE.",
        when_to_use="Use when user enumeration is still missing after basic SMB connectivity checks.",
        arg_shape="host:port",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=("internal_safe_enum",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="smb-enum-users.nse",
        purpose="Enumerate SMB and domain user accounts with Nmap NSE.",
        when_to_use="Use when user enumeration is still missing after basic SMB connectivity checks.",
        arg_shape="host:port",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=("internal_safe_enum",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="smb-enum-policies",
        purpose="Enumerate SMB domain and password policy hints with Nmap NSE.",
        when_to_use="Use when domain or password policy posture is still missing and SMB negotiation is working.",
        arg_shape="host:port",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="smb-enum-users-rpc",
        purpose="Enumerate domain users over rpcclient.",
        when_to_use="Use when rpcclient-based user enumeration is justified after basic SMB/RPC reachability checks.",
        arg_shape="host",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="polenum",
        purpose="Legacy Windows password policy enumeration.",
        when_to_use="Use when anonymous or guest SMB access might expose domain password policy details.",
        arg_shape="host",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="samrdump",
        purpose="Legacy SAMR-based user and group enumeration.",
        when_to_use="Use only when SMB/RPC access is working and deeper identity enumeration is justified.",
        arg_shape="host",
        phase_tags=("targeted_checks",),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="msrpc-enum.nse",
        purpose="Enumerate Microsoft RPC interfaces and endpoint mapper details.",
        when_to_use="Use after basic MSRPC fingerprinting when RPC interface follow-up is justified.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "protocol_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="netexec",
        purpose="Modern SMB-aware internal enumeration and posture validation.",
        when_to_use="Use when safe SMB internal enumeration is missing and a modern shares/users/password-policy check is justified.",
        arg_shape="host",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=("internal_safe_enum",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="mysql-info.nse",
        purpose="Safely fingerprint a MySQL or MariaDB service with Nmap NSE.",
        when_to_use="Use when an internal MySQL-family service needs bounded version, protocol, or auth-plugin fingerprinting.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "protocol_checks"),
        prompt_groups=("internal_safe_enum",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="pgsql-info.nse",
        purpose="Safely fingerprint a PostgreSQL service with Nmap NSE.",
        when_to_use="Use when an internal PostgreSQL service needs bounded version, auth-method, or SSL posture fingerprinting.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "protocol_checks"),
        prompt_groups=("internal_safe_enum",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="ms-sql-info.nse",
        purpose="Safely fingerprint a Microsoft SQL Server service with Nmap NSE.",
        when_to_use="Use when an internal Microsoft SQL Server endpoint needs bounded version and instance posture fingerprinting.",
        arg_shape="host:port",
        phase_tags=("service_fingerprint", "protocol_checks"),
        prompt_groups=("internal_safe_enum",),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="responder",
        purpose="Operator-reviewed credential-capture listener preparation for internal relay testing.",
        when_to_use="Use only in approved internal pentest workflows when capture or poisoning validation is justified and an operator can choose the segment interface.",
        arg_shape="host",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
    SchedulerToolPromptInfo(
        tool_id="ntlmrelayx",
        purpose="Operator-reviewed NTLM relay workflow preparation against a chosen internal target.",
        when_to_use="Use only after approved internal relay preconditions exist, such as SMB signing disabled or another explicit NTLM relay target.",
        arg_shape="host",
        phase_tags=("protocol_checks", "targeted_checks"),
        prompt_groups=(),
        safe_parallel=False,
    ),
)

_TOOL_PROMPT_REGISTRY: Dict[str, SchedulerToolPromptInfo] = {
    entry.tool_id: entry for entry in _TOOL_PROMPT_ENTRIES
}
_PROMPT_GROUP_ORDER: Dict[str, Tuple[str, ...]] = {}
for _entry in _TOOL_PROMPT_ENTRIES:
    for _group in _entry.prompt_groups:
        _PROMPT_GROUP_ORDER.setdefault(_group, tuple())
for _group in list(_PROMPT_GROUP_ORDER.keys()):
    _PROMPT_GROUP_ORDER[_group] = tuple(
        entry.tool_id for entry in _TOOL_PROMPT_ENTRIES if _group in entry.prompt_groups
    )

_BASE_COMMAND_RE = re.compile(r"\b([A-Za-z0-9_.-]+)\b")


def infer_arg_shape(command_template: str = "") -> str:
    text = str(command_template or "")
    if "[WEB_URL]" in text:
        return "web_url"
    if "[URL]" in text:
        return "url"
    if "[IP]" in text and "[PORT]" in text:
        return "host:port"
    if "[IP]" in text:
        return "host"
    return ""


def _tooling_purpose_aliases() -> Dict[str, str]:
    aliases: Dict[str, str] = {}
    for spec in list_legion_tool_specs():
        purpose = str(spec.purpose or "").strip()
        for command in spec.commands:
            key = str(command or "").strip().lower()
            if key and purpose and key not in aliases:
                aliases[key] = purpose
        spec_key = str(spec.key or "").strip().lower()
        if spec_key and purpose and spec_key not in aliases:
            aliases[spec_key] = purpose
    return aliases


_TOOLING_PURPOSE_ALIASES = _tooling_purpose_aliases()


def _first_command_token(text: str) -> str:
    lowered = str(text or "").strip()
    if not lowered:
        return ""
    for probe in ("command -v ", "if command -v "):
        marker = lowered.find(probe)
        if marker >= 0:
            start = marker + len(probe)
            tail = lowered[start:]
            match = _BASE_COMMAND_RE.search(tail)
            if match:
                return str(match.group(1) or "").strip().lower()
    match = _BASE_COMMAND_RE.search(lowered)
    if not match:
        return ""
    return str(match.group(1) or "").strip().lower()


def _fallback_purpose(*, tool_id: str, label: str = "", command_template: str = "") -> str:
    candidates = [
        str(tool_id or "").strip().lower(),
        _first_command_token(command_template),
    ]
    for candidate in candidates:
        if candidate and candidate in _TOOLING_PURPOSE_ALIASES:
            return _TOOLING_PURPOSE_ALIASES[candidate]
    text = str(label or "").strip()
    if text:
        return f"{text} follow-up action."
    return "Governed follow-up action."


def _fallback_when_to_use(*, service_scope: str = "", purpose: str = "") -> str:
    scope = str(service_scope or "").strip()
    if scope:
        return f"Use when {scope} coverage still needs bounded follow-up."
    if purpose:
        return f"Use when {purpose[:72].rstrip('.')} is still needed."
    return "Use when the current target still needs bounded follow-up."


def get_scheduler_tool_prompt_info(
        tool_id: str,
        *,
        label: str = "",
        command_template: str = "",
        service_scope: str = "",
) -> SchedulerToolPromptInfo:
    key = str(tool_id or "").strip().lower()
    if key in _TOOL_PROMPT_REGISTRY:
        return _TOOL_PROMPT_REGISTRY[key]
    purpose = _fallback_purpose(tool_id=key, label=label, command_template=command_template)
    return SchedulerToolPromptInfo(
        tool_id=key,
        purpose=purpose,
        when_to_use=_fallback_when_to_use(service_scope=service_scope, purpose=purpose),
        arg_shape=infer_arg_shape(command_template),
        phase_tags=(),
        prompt_groups=(),
        safe_parallel=False,
    )


def tool_ids_for_prompt_group(group: str) -> List[str]:
    key = str(group or "").strip()
    if not key:
        return []
    return list(_PROMPT_GROUP_ORDER.get(key, ()))


def phase_tags_for_tool(tool_id: str) -> Tuple[str, ...]:
    return tuple(get_scheduler_tool_prompt_info(tool_id).phase_tags)


def iter_scheduler_tool_prompt_entries() -> Iterable[SchedulerToolPromptInfo]:
    return tuple(_TOOL_PROMPT_ENTRIES)
