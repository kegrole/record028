"""Evaluate script requests against one or more parsed CSP policies."""

from .hashcheck import hash_matches, nonce_matches
from .sources import external_source_allows


SCRIPT_DIRECTIVE_CHAINS = {
    "external": ("script-src-elem", "script-src", "default-src"),
    "inline": ("script-src", "default-src"),
    "event-handler": ("script-src-attr", "script-src", "default-src"),
    "eval": ("script-src", "default-src"),
}


def evaluate_request(policy, request):
    request_type = _request_type(request)
    directive = _find_directive(policy, request_type)
    if directive is None:
        return {
            "directive": "<none>",
            "request_id": request.get("id"),
            "allowed": True,
            "reason": "策略未声明适用的脚本指令，按无限制处理",
        }

    if directive.invalid_none:
        return _denial(
            directive,
            request,
            "'none' 与其它来源并存，该 source-list 整体无效并禁止全部",
        )

    if request_type == "eval":
        return _evaluate_eval(directive, request)
    if request_type in ("inline", "event-handler"):
        return _evaluate_inline(directive, request, request_type)
    return _evaluate_external(directive, request, policy.document_origin)


def evaluate(policies, requests):
    enforced_results = []
    report_results = []
    enforced = [policy for policy in policies if policy.mode != "report-only"]
    report_only = [policy for policy in policies if policy.mode == "report-only"]

    for request in requests:
        applicable = _applicable_policies(request, enforced)
        policy_results = [evaluate_request(policy, request) for policy in applicable]
        enforced_results.append(_combine_results(request, policy_results))

        for policy in report_only:
            result = evaluate_request(policy, request)
            result["reason"] = "[report-only:{}] {}".format(policy.policy_id, result["reason"])
            report_results.append(result)

    return {
        "enforced": enforced_results,
        "report_only": report_results,
        "unsafe_inline_locations": _keyword_locations(policies, "'unsafe-inline'"),
        "unsafe_eval_locations": _keyword_locations(policies, "'unsafe-eval'"),
    }


def _request_type(request):
    explicit = request.get("type")
    if explicit:
        return explicit.lower()
    if request.get("inline_text") is not None:
        return "inline"
    return "external"


def _find_directive(policy, request_type):
    for name in SCRIPT_DIRECTIVE_CHAINS[request_type]:
        if name in policy.directives:
            return policy.directives[name]
    return None


def _evaluate_eval(directive, request):
    if _has_keyword(directive, "'unsafe-eval'"):
        return _allow(directive, request, "命中 'unsafe-eval'，允许动态求值")
    return _denial(directive, request, "缺少 'unsafe-eval'，动态求值被拒绝")


def _evaluate_external(directive, request, document_origin):
    strict_dynamic = _has_keyword(directive, "'strict-dynamic'")
    trusted = bool(request.get("trusted_dynamic"))
    if strict_dynamic and trusted:
        return _allow(directive, request, "命中 'strict-dynamic' 且请求由受信脚本传播")

    request_nonce = request.get("nonce")
    if request_nonce is not None:
        for source in directive.sources:
            if source.kind == "nonce" and nonce_matches(request_nonce, source.value):
                return _allow(directive, request, "nonce 与声明值逐字节一致")

    if strict_dynamic:
        return _denial(
            directive,
            request,
            "'strict-dynamic' 生效时忽略 host、scheme 与 'self'，且没有匹配 nonce 或受信传播",
        )

    for source in directive.sources:
        if external_source_allows(
            source,
            request["url"],
            document_origin,
            request_nonce=request_nonce,
        ):
            return _allow(directive, request, "来源表达式匹配：{}".format(source.raw))
    return _denial(directive, request, "没有任何 host-source、scheme-source、'self' 或 nonce 匹配该外链脚本")


def _evaluate_inline(directive, request, request_type):
    content = request.get("inline_text", "")
    request_nonce = request.get("nonce")
    nonce_sources = [source for source in directive.sources if source.kind == "nonce"]
    hash_sources = [source for source in directive.sources if source.kind == "hash"]

    if request_nonce is not None:
        for source in nonce_sources:
            if nonce_matches(request_nonce, source.value):
                return _allow(directive, request, "内联脚本 nonce 与声明值逐字节一致")

    for source in hash_sources:
        if request_type == "event-handler" and not _has_keyword(directive, "'unsafe-hashes'"):
            continue
        if hash_matches(content, source.algorithm, source.value):
            if request_type == "event-handler":
                return _allow(directive, request, "事件处理器内容哈希匹配且 'unsafe-hashes' 生效")
            return _allow(directive, request, "内联脚本内容哈希与声明基值完全一致")

    suppresses_unsafe_inline = bool(nonce_sources or hash_sources)
    strict_dynamic = _has_keyword(directive, "'strict-dynamic'")
    if _has_keyword(directive, "'unsafe-inline'") and not suppresses_unsafe_inline and not strict_dynamic:
        if request_type == "event-handler" and not _has_keyword(directive, "'unsafe-hashes'"):
            return _allow(directive, request, "命中 'unsafe-inline'，允许内联事件处理器")
        return _allow(directive, request, "命中 'unsafe-inline'，允许内联脚本")

    if request_nonce is not None and nonce_sources:
        return _denial(directive, request, "nonce 与声明值逐字节不一致")
    if hash_sources:
        return _denial(directive, request, "脚本内容的哈希基值与所有声明哈希均不一致")
    return _denial(directive, request, "缺少匹配的 nonce、哈希或 'unsafe-inline'")


def _applicable_policies(request, enforced):
    policy_ids = request.get("policy_ids")
    if not policy_ids:
        return enforced
    selected = set(str(policy_id) for policy_id in policy_ids)
    return [policy for policy in enforced if policy.policy_id in selected]


def _combine_results(request, results):
    if not results:
        return {
            "directive": "<none>",
            "request_id": request.get("id"),
            "allowed": True,
            "reason": "没有适用的拦截策略，按允许处理",
        }
    allowed = all(result["allowed"] for result in results)
    directive_names = sorted({result["directive"] for result in results})
    if allowed:
        reason = "所有适用策略均允许；交集结果为允许"
    else:
        denied = [result["reason"] for result in results if not result["allowed"]]
        reason = "多策略交集拒绝：{}".format("；".join(denied))
    return {
        "directive": ",".join(directive_names),
        "request_id": request.get("id"),
        "allowed": allowed,
        "reason": reason,
    }


def _keyword_locations(policies, keyword):
    locations = []
    for policy in policies:
        for directive in policy.directives.values():
            if _has_keyword(directive, keyword):
                locations.append({
                    "policy_id": policy.policy_id,
                    "directive": directive.name,
                    "mode": policy.mode,
                })
    return locations


def _has_keyword(directive, keyword):
    return any(
        source.kind == "keyword" and source.value == keyword
        for source in directive.sources
    )


def _allow(directive, request, reason):
    return {
        "directive": directive.name,
        "request_id": request.get("id"),
        "allowed": True,
        "reason": reason,
    }


def _denial(directive, request, reason):
    return {
        "directive": directive.name,
        "request_id": request.get("id"),
        "allowed": False,
        "reason": reason,
    }
