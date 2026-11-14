"""Parsing and matching of CSP source-list expressions."""

from dataclasses import dataclass
from urllib.parse import urlsplit

from .hashcheck import HASH_ALGORITHMS, nonce_matches


QUOTED_KEYWORDS = frozenset({
    "'none'",
    "'self'",
    "'unsafe-inline'",
    "'unsafe-eval'",
    "'strict-dynamic'",
    "'unsafe-hashes'",
})

DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
    "ftp": 21,
}


@dataclass(frozen=True)
class HostSource:
    scheme: str = None
    host: str = None
    port: int = None
    path: str = ""
    subdomain_wildcard: bool = False
    any_host: bool = False
    port_wildcard: bool = False


@dataclass(frozen=True)
class SourceExpression:
    kind: str
    value: str = None
    algorithm: str = None
    host: HostSource = None
    raw: str = ""


def parse_source(token):
    lowered = token.lower()
    if lowered in QUOTED_KEYWORDS:
        return SourceExpression(kind="keyword", value=lowered, raw=token)

    if lowered.startswith("'nonce-") and token.endswith("'"):
        value = token[7:-1]
        if value:
            return SourceExpression(kind="nonce", value=value, raw=token)

    for algorithm in HASH_ALGORITHMS:
        prefix = "'" + algorithm + "-"
        if lowered.startswith(prefix) and token.endswith("'"):
            value = token[len(prefix):-1]
            if value:
                return SourceExpression(
                    kind="hash",
                    value=value,
                    algorithm=algorithm,
                    raw=token,
                )

    if token.endswith(":") and len(token) > 1:
        return SourceExpression(kind="scheme", value=token[:-1].lower(), raw=token)

    host_source = _parse_host_source(token)
    if host_source is not None:
        return SourceExpression(kind="host", host=host_source, raw=token)

    return SourceExpression(kind="unknown", raw=token)


def _parse_host_source(token):
    if not token or token.startswith("'") or token.endswith(":"):
        return None

    scheme = None
    remainder = token
    if "://" in token:
        parsed = urlsplit(token)
        if not parsed.netloc:
            return None
        scheme = parsed.scheme.lower()
        remainder = token[token.index("://") + 3:]
        path = parsed.path or ""
    else:
        parsed = urlsplit("//" + token)
        if not parsed.netloc:
            return None
        path = parsed.path or ""

    netloc = parsed.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]

    host_part = netloc
    port = None
    port_wildcard = False
    if host_part.startswith("["):
        end = host_part.find("]")
        if end < 0:
            return None
        host = host_part[1:end].lower()
        tail = host_part[end + 1:]
        if tail.startswith(":"):
            host_part_port = tail[1:]
            port, port_wildcard = _parse_port(host_part_port)
            if port is None and not port_wildcard:
                return None
    else:
        pieces = host_part.rsplit(":", 1)
        host = pieces[0].lower()
        if len(pieces) == 2:
            port, port_wildcard = _parse_port(pieces[1])
            if port is None and not port_wildcard:
                return None

    if not host:
        return None

    any_host = host == "*"
    subdomain_wildcard = False
    if not any_host and host.startswith("*."):
        subdomain_wildcard = True
        host = host[2:]
        if not host:
            return None

    return HostSource(
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        subdomain_wildcard=subdomain_wildcard,
        any_host=any_host,
        port_wildcard=port_wildcard,
    )


def _parse_port(value):
    if value == "*":
        return None, True
    if value.isdigit():
        port = int(value)
        if 0 <= port <= 65535:
            return port, False
    return None, False


def external_source_allows(source, request_url, document_origin, request_nonce=None):
    if source.kind == "nonce":
        return nonce_matches(request_nonce, source.value)
    if source.kind != "host" and source.kind != "scheme" and source.kind != "keyword":
        return False
    if source.kind == "keyword":
        return source.value == "'self'" and _origin_matches(request_url, document_origin)

    parsed = urlsplit(request_url)
    if source.kind == "scheme":
        return parsed.scheme.lower() == source.value

    host = source.host
    effective_scheme = host.scheme or (urlsplit(document_origin).scheme if document_origin else None)
    if not effective_scheme or parsed.scheme.lower() != effective_scheme.lower():
        return False
    if not _host_matches(host, parsed.hostname or ""):
        return False
    if not _port_matches(host, parsed.port, effective_scheme):
        return False
    return _path_matches(host.path, parsed.path or "/")


def _host_matches(host, request_host):
    request_host = request_host.lower()
    if host.any_host:
        return bool(request_host)
    if host.subdomain_wildcard:
        return request_host == host.host or request_host.endswith("." + host.host)
    return request_host == host.host


def _port_matches(host, request_port, scheme):
    expected = request_port or DEFAULT_PORTS.get(scheme.lower())
    if host.port_wildcard:
        return request_port is not None or expected is not None
    allowed = host.port
    if allowed is None:
        allowed = DEFAULT_PORTS.get(scheme.lower())
    return expected == allowed


def _path_matches(allowed_path, request_path):
    if not allowed_path:
        return True
    if request_path == allowed_path:
        return True
    if allowed_path.endswith("/"):
        return request_path.startswith(allowed_path)
    return False


def _origin_matches(request_url, document_origin):
    if not document_origin:
        return False
    request = urlsplit(request_url)
    document = urlsplit(document_origin)
    request_port = request.port or DEFAULT_PORTS.get(request.scheme.lower())
    document_port = document.port or DEFAULT_PORTS.get(document.scheme.lower())
    return (
        request.scheme.lower() == document.scheme.lower()
        and (request.hostname or "").lower() == (document.hostname or "").lower()
        and request_port == document_port
    )
