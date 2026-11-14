"""CSP header and policy JSON parsing using only the Python standard library."""

from dataclasses import dataclass, field

from .sources import parse_source


KNOWN_DIRECTIVES = frozenset({
    "default-src",
    "child-src",
    "connect-src",
    "font-src",
    "frame-src",
    "img-src",
    "manifest-src",
    "media-src",
    "object-src",
    "prefetch-src",
    "script-src",
    "script-src-elem",
    "script-src-attr",
    "style-src",
    "style-src-elem",
    "style-src-attr",
    "worker-src",
    "base-uri",
    "form-action",
    "frame-ancestors",
    "navigate-to",
    "report-uri",
    "report-to",
    "sandbox",
    "require-trusted-types-for",
    "trusted-types",
    "upgrade-insecure-requests",
})


@dataclass(frozen=True)
class Directive:
    name: str
    sources: tuple
    invalid_none: bool = False
    raw: str = ""


@dataclass(frozen=True)
class Policy:
    policy_id: str
    header: str
    mode: str = "enforce"
    document_origin: str = None
    directives: dict = field(default_factory=dict)


def parse_header(header, policy_id=None, mode="enforce", document_origin=None):
    directives = {}
    normalized_mode = mode.lower() if mode else "enforce"
    for raw_directive in header.split(";"):
        tokens = raw_directive.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in KNOWN_DIRECTIVES:
            continue
        if name in directives:
            continue
        sources = tuple(parse_source(token) for token in tokens[1:])
        invalid_none = _contains_none_with_other_sources(sources)
        directives[name] = Directive(
            name=name,
            sources=sources,
            invalid_none=invalid_none,
            raw=raw_directive.strip(),
        )
    return Policy(
        policy_id=str(policy_id) if policy_id is not None else None,
        header=header,
        mode=normalized_mode,
        document_origin=document_origin,
        directives=directives,
    )


def load_policies(value):
    if isinstance(value, dict):
        value = value.get("policies", [])
    policies = []
    for index, item in enumerate(value):
        policies.append(
            parse_header(
                item["header"],
                policy_id=item.get("id", "policy-{}".format(index + 1)),
                mode=item.get("mode", "enforce"),
                document_origin=item.get("document_origin"),
            )
        )
    return policies


def _contains_none_with_other_sources(sources):
    has_none = any(
        source.kind == "keyword" and source.value == "'none'"
        for source in sources
    )
    return has_none and len(sources) > 1
