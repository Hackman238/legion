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
import ssl


def defaultUserAgent() -> str:
    return "Mozilla/5.0 (X11; Linux x86_64; rv:22.0) Gecko/20100101 Firefox/22.0 Iceweasel/22.0"


def _is_certificate_error(message: str) -> bool:
    lowered = str(message or "").lower()
    cert_tokens = [
        "certificate verify failed",
        "self-signed certificate",
        "unknown ca",
        "certificate has expired",
        "hostname mismatch",
        "certificate",
    ]
    return any(token in lowered for token in cert_tokens)


def isHttps(host, port) -> bool:
    from urllib.error import URLError
    try:
        from urllib.request import Request, urlopen
        headers = {"User-Agent": defaultUserAgent()}
        req = Request(f"https://{host}:{port}", headers=headers)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        urlopen(req, timeout=5, context=context).read(1)
        return True
    except URLError as e:
        reason = str(getattr(e, "reason", e))
        if 'Forbidden' in reason or _is_certificate_error(reason):
            return True
        return False
    except ssl.CertificateError:
        return True
    except ssl.SSLError as e:
        return _is_certificate_error(str(e))
