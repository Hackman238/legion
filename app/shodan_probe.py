from __future__ import annotations

import argparse
import json
import ipaddress
import sys
from typing import Any, Dict, List
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from app.hostsfile import normalize_hostname_alias, registrable_root_domain


API_BASE_URL = "https://api.shodan.io"


def _normalize_shodan_target(target: str) -> str:
    hostname = normalize_hostname_alias(str(target or ""))
    if not hostname or "." not in hostname:
        return ""
    try:
        ipaddress.ip_address(hostname)
        return ""
    except ValueError:
        return hostname


def _perform_request(path: str, *, api_key: str, params: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
    query_string = urlencode({key: value for key, value in params.items() if value not in (None, "")})
    request = Request(
        f"{API_BASE_URL.rstrip('/')}/{path.lstrip('/')}?{query_string}",
        headers={
            "Accept": "application/json",
            "User-Agent": "Legion Shodan Probe/1.0",
        },
    )
    with urlopen(request, timeout=timeout) as response:
        payload = response.read().decode("utf-8", errors="replace")
    return json.loads(payload or "{}")


def _search_query_for_target(hostname: str) -> str:
    exact = str(hostname or "").strip()
    if not exact:
        return ""
    return f'hostname:"{exact}"'


def _trim_matches(matches: Any, limit: int) -> List[Dict[str, Any]]:
    rows = list(matches or []) if isinstance(matches, list) else []
    trimmed: List[Dict[str, Any]] = []
    for item in rows[: max(1, min(int(limit or 25), 50))]:
        if isinstance(item, dict):
            trimmed.append(item)
    return trimmed


def run_shodan_probe(target: str, api_key: str, *, limit: int = 25, timeout: int = 30) -> Dict[str, Any]:
    exact_hostname = _normalize_shodan_target(target)
    root_domain = registrable_root_domain(exact_hostname)
    if not exact_hostname or not root_domain:
        return {
            "input_target": str(target or ""),
            "exact_hostname": "",
            "root_domain": "",
            "supported": False,
            "dns_resolve": {},
            "search_query": "",
            "total": 0,
            "matches": [],
        }

    dns_resolve = _perform_request(
        "dns/resolve",
        api_key=api_key,
        params={
            "key": api_key,
            "hostnames": exact_hostname,
        },
        timeout=timeout,
    )
    dns_domain = _perform_request(
        f"dns/domain/{root_domain}",
        api_key=api_key,
        params={
            "key": api_key,
            "page": 1,
        },
        timeout=timeout,
    )
    search_query = _search_query_for_target(exact_hostname)
    search_params = {
        "key": api_key,
        "query": search_query,
        "minify": "true",
        "page": 1,
    }
    try:
        search_payload = _perform_request(
            "shodan/host/search",
            api_key=api_key,
            params=search_params,
            timeout=timeout,
        )
    except HTTPError as exc:
        if int(getattr(exc, "code", 0) or 0) not in {400, 422}:
            raise
        fallback_query = f"hostname:{exact_hostname}"
        search_params["query"] = fallback_query
        search_payload = _perform_request(
            "shodan/host/search",
            api_key=api_key,
            params=search_params,
            timeout=timeout,
        )
        search_query = fallback_query

    matches = _trim_matches(search_payload.get("matches", []), limit)
    return {
        "input_target": str(target or ""),
        "exact_hostname": exact_hostname,
        "root_domain": root_domain,
        "supported": True,
        "dns_resolve": dns_resolve if isinstance(dns_resolve, dict) else {},
        "dns_domain": dns_domain if isinstance(dns_domain, dict) else {},
        "search_query": search_query,
        "total": int(search_payload.get("total", len(matches)) or 0),
        "matches": matches,
    }


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Search Shodan for hostname or certificate matches related to an external hostname.")
    parser.add_argument("--target", required=True, help="Input hostname or domain.")
    parser.add_argument("--api-key", required=True, help="Shodan API key.")
    parser.add_argument("--output", required=True, help="Output JSON file path.")
    parser.add_argument("--limit", type=int, default=25, help="Max Shodan matches to retain in output.")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds.")
    return parser


def main(argv: Any = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    try:
        payload = run_shodan_probe(
            str(args.target or ""),
            str(args.api_key or ""),
            limit=int(args.limit or 25),
            timeout=int(args.timeout or 30),
        )
    except HTTPError as exc:
        message = exc.read().decode("utf-8", errors="replace") if getattr(exc, "fp", None) else str(exc)
        print(f"shodan http error {getattr(exc, 'code', 'unknown')}: {message}", file=sys.stderr)
        return 1
    except URLError as exc:
        print(f"shodan network error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"shodan probe failed: {exc}", file=sys.stderr)
        return 1

    with open(str(args.output or ""), "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)

    dns_resolve = payload.get("dns_resolve", {}) if isinstance(payload.get("dns_resolve", {}), dict) else {}
    print(
        "shodan "
        f"exact_hostname={payload.get('exact_hostname', '')} "
        f"dns_hits={1 if payload.get('exact_hostname', '') in dns_resolve else 0} "
        f"matches={int(payload.get('total', 0) or 0)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
