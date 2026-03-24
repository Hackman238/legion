from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from app.hostsfile import registrable_root_domain


API_BASE_URL = "https://buckets.grayhatwarfare.com/api/v2"
BUCKET_TYPES = "aws,azure,gcp,dos,ali"


def grayhat_root_keyword(domain: str) -> str:
    root_domain = registrable_root_domain(domain)
    if not root_domain:
        return ""
    label = str(root_domain.split(".", 1)[0] or "").strip().lower()
    tokens = ["".join(ch for ch in token if ch.isalnum()) for token in label.replace("_", "-").split("-")]
    normalized = [token for token in tokens if token]
    if not normalized:
        return ""
    return "-".join(normalized)


def grayhat_domain_regex(domain: str) -> str:
    keyword = grayhat_root_keyword(domain)
    if not keyword:
        return ""
    tokens = [token for token in keyword.replace("-", " ").split() if token]
    if not tokens:
        return ""
    return ".*" + ".*".join(tokens) + ".*"


def _perform_request(endpoint: str, *, api_key: str, params: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
    query_string = urlencode({key: value for key, value in params.items() if value not in (None, "")})
    request = Request(
        f"{API_BASE_URL.rstrip('/')}/{endpoint.lstrip('/')}?{query_string}",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "Legion GrayhatWarfare Probe/1.0",
        },
    )
    with urlopen(request, timeout=timeout) as response:
        payload = response.read().decode("utf-8", errors="replace")
    return json.loads(payload or "{}")


def run_grayhatwarfare_probe(domain: str, api_key: str, *, limit: int = 25, timeout: int = 30) -> Dict[str, Any]:
    root_domain = registrable_root_domain(domain)
    keyword = grayhat_root_keyword(domain)
    regex = grayhat_domain_regex(domain)

    if not root_domain or not keyword or not regex:
        return {
            "input_domain": str(domain or ""),
            "root_domain": "",
            "keyword": "",
            "file_regex": "",
            "supported": False,
            "buckets": [],
            "files": [],
            "meta": {
                "bucket_results": 0,
                "file_results": 0,
            },
        }

    bucket_params = {
        "keywords": keyword,
        "limit": max(1, min(int(limit or 25), 1000)),
        "order": "fileCount",
        "direction": "desc",
    }
    file_params = {
        "keywords": regex,
        "regexp": "1",
        "noautocorrect": "1",
        "full-path": "1",
        "types": BUCKET_TYPES,
        "limit": max(1, min(int(limit or 25), 1000)),
    }

    buckets_payload = _perform_request("buckets", api_key=api_key, params=bucket_params, timeout=timeout)
    files_payload: Dict[str, Any]
    try:
        files_payload = _perform_request("files", api_key=api_key, params=file_params, timeout=timeout)
    except HTTPError as exc:
        if int(getattr(exc, "code", 0) or 0) not in {400, 401, 402, 403, 422}:
            raise
        fallback_file_params = {
            "keywords": keyword,
            "full-path": "1",
            "types": BUCKET_TYPES,
            "limit": max(1, min(int(limit or 25), 1000)),
        }
        files_payload = _perform_request("files", api_key=api_key, params=fallback_file_params, timeout=timeout)
        files_payload.setdefault("meta", {})
        files_payload["meta"]["fallbackKeywordQuery"] = keyword

    return {
        "input_domain": str(domain or ""),
        "root_domain": root_domain,
        "keyword": keyword,
        "file_regex": regex,
        "supported": True,
        "bucket_query": bucket_params,
        "file_query": file_params,
        "buckets": list(buckets_payload.get("buckets", []) or []),
        "files": list(files_payload.get("files", []) or []),
        "meta": {
            "bucket_results": int(((buckets_payload.get("meta", {}) if isinstance(buckets_payload.get("meta", {}), dict) else {}).get("results", 0)) or 0),
            "file_results": int(((files_payload.get("meta", {}) if isinstance(files_payload.get("meta", {}), dict) else {}).get("results", 0)) or 0),
            "bucket_notice": str(((buckets_payload.get("meta", {}) if isinstance(buckets_payload.get("meta", {}), dict) else {}).get("notice", "")) or ""),
            "file_notice": str(((files_payload.get("meta", {}) if isinstance(files_payload.get("meta", {}), dict) else {}).get("notice", "")) or ""),
            "file_regex_notice": str(((files_payload.get("meta", {}) if isinstance(files_payload.get("meta", {}), dict) else {}).get("regexNotice", "")) or ""),
            "file_fallback_keyword_query": str(((files_payload.get("meta", {}) if isinstance(files_payload.get("meta", {}), dict) else {}).get("fallbackKeywordQuery", "")) or ""),
        },
    }


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Search Grayhat Warfare for public buckets/files related to a root domain.")
    parser.add_argument("--domain", required=True, help="Input hostname or domain.")
    parser.add_argument("--api-key", required=True, help="Grayhat Warfare API key.")
    parser.add_argument("--output", required=True, help="Output JSON file path.")
    parser.add_argument("--limit", type=int, default=25, help="Max results to request from each endpoint.")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds.")
    return parser


def main(argv: Any = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    try:
        payload = run_grayhatwarfare_probe(
            str(args.domain or ""),
            str(args.api_key or ""),
            limit=int(args.limit or 25),
            timeout=int(args.timeout or 30),
        )
    except HTTPError as exc:
        message = exc.read().decode("utf-8", errors="replace") if getattr(exc, "fp", None) else str(exc)
        print(f"grayhatwarfare http error {getattr(exc, 'code', 'unknown')}: {message}", file=sys.stderr)
        return 1
    except URLError as exc:
        print(f"grayhatwarfare network error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"grayhatwarfare probe failed: {exc}", file=sys.stderr)
        return 1

    with open(str(args.output or ""), "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)

    meta = payload.get("meta", {}) if isinstance(payload.get("meta", {}), dict) else {}
    print(
        "grayhatwarfare "
        f"root_domain={payload.get('root_domain', '')} "
        f"bucket_results={int(meta.get('bucket_results', 0) or 0)} "
        f"file_results={int(meta.get('file_results', 0) or 0)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
