"""Extra OWASP Top 10 static checks (compact regex), one function per control.

Philosophy: a control must be *demonstrated* to score high — absence of a
defense is penalised, not rewarded. All thresholds come from config/scoring.yaml.
Each function returns a CheckResult; the runner attaches the OWASP tag.
"""
from __future__ import annotations

import re
from typing import List, Optional, Sequence, Tuple

from ..models import CheckResult

Source = Tuple[str, str]  # (relative_path, file_text)


def _joined(sources: Sequence[Source]) -> str:
    return "\n".join(text for _, text in sources)


def _clamp(score: float) -> float:
    return max(0.0, min(100.0, score))


def _mk(check_id: str, label: str, score: float, cfg: dict, *,
        passed: bool, reasons: List[str], evidence: List[str]) -> CheckResult:
    return CheckResult(
        check_id=check_id, category="static", label=label,
        score=_clamp(score), weight=float(cfg.get("weight", 0)),
        passed=passed, penalty_reasons=reasons, evidence=evidence,
    )


# A01 — CSRF protection. State-changing POST forms need a token / Flask-WTF.
_CSRF_MARKERS = re.compile(
    r"""csrf_token|CSRFProtect|flask_wtf|WTF_CSRF|csrf\.protect|X-CSRF|csrf_protect""",
    re.IGNORECASE,
)


def check_csrf_protection(
    sources: Sequence[Source], cfg: dict,
    templates: Optional[Sequence[Source]] = None,
) -> CheckResult:
    haystack = _joined(sources) + "\n" + _joined(templates or [])
    hit = _CSRF_MARKERS.search(haystack)
    if hit:
        return _mk("csrf_protection", "CSRF 보호", float(cfg.get("score_protected", 100)),
                   cfg, passed=True, reasons=[], evidence=[hit.group(0)])
    return _mk("csrf_protection", "CSRF 보호", float(cfg.get("score_missing", 0)),
               cfg, passed=False,
               reasons=["폼/요청에 CSRF 토큰·Flask-WTF 등 CSRF 방어가 없음 → 상태변경 요청 위조 가능"],
               evidence=[])


# A05 — Content-Security-Policy as XSS defense-in-depth. autoescape is the Jinja
# default (free); a CSP constraining script sources must be actively set. Look in
# source (response headers / Talisman / flask-seasurf-style) and template meta tags.
_CSP_MARKERS = re.compile(
    r"""Content-Security-Policy|content_security_policy|["']CSP["']|Talisman\s*\(|"""
    r"""http-equiv\s*=\s*["']Content-Security-Policy["']""",
    re.IGNORECASE,
)


def check_csp(
    sources: Sequence[Source], cfg: dict,
    templates: Optional[Sequence[Source]] = None,
) -> CheckResult:
    haystack = _joined(sources) + "\n" + _joined(templates or [])
    hit = _CSP_MARKERS.search(haystack)
    if hit:
        return _mk("csp", "CSP(XSS 심층방어)", float(cfg.get("score_present", 100)),
                   cfg, passed=True, reasons=[], evidence=[hit.group(0)])
    return _mk("csp", "CSP(XSS 심층방어)", float(cfg.get("score_missing", 0)),
               cfg, passed=False,
               reasons=["Content-Security-Policy 미설정 → 자동escape 우회(속성/JS 컨텍스트) XSS에 무방비. "
                        "autoescape는 프레임워크 기본값일 뿐 CSP로 스크립트 출처를 제한해야 함"],
               evidence=[])


# A04 — weak default secret. os.environ.get("SECRET_KEY", "<literal>") fallback,
# which hardcoded_secret skips because it sees an env reference.
_WEAK_DEFAULT = re.compile(
    r"""(?:environ\.get|getenv)\s*\(\s*['"][^'"]*(?:SECRET|KEY|PASSWORD)[^'"]*['"]\s*,\s*(?P<def>['"][^'"]*['"])""",
    re.IGNORECASE,
)


def check_weak_default_secret(sources: Sequence[Source], cfg: dict) -> CheckResult:
    reasons: List[str] = []
    evidence: List[str] = []
    for path, text in sources:
        for m in _WEAK_DEFAULT.finditer(text):
            default = m.group("def").strip("'\"")
            if not default:
                continue  # empty fallback => still needs env, acceptable
            lineno = text.count("\n", 0, m.start()) + 1
            reasons.append(f"{path}:{lineno} 환경변수 미설정 시 하드코딩 기본 시크릿으로 폴백")
            evidence.append(f"{path}:{lineno}: {m.group(0)[:120]}")
    if reasons:
        return _mk("weak_default_secret", "약한 기본 시크릿",
                   float(cfg.get("score_weak", 0)), cfg,
                   passed=False, reasons=reasons, evidence=evidence)
    return _mk("weak_default_secret", "약한 기본 시크릿",
               float(cfg.get("score_ok", 100)), cfg,
               passed=True, reasons=[], evidence=[])


# A08 — insecure deserialization / dynamic exec on request data.
_INSECURE_DESER = re.compile(
    r"""pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Safe)|(?<![\w.])(eval|exec)\s*\(""",
    re.IGNORECASE,
)
_REQUEST_NEAR = re.compile(r"""request\.|request\[""")


def check_insecure_deserialization(sources: Sequence[Source], cfg: dict) -> CheckResult:
    reasons: List[str] = []
    evidence: List[str] = []
    for path, text in sources:
        uses_request = bool(_REQUEST_NEAR.search(text))
        for m in _INSECURE_DESER.finditer(text):
            token = m.group(0)
            # eval/exec only matter if the app also handles request data.
            if token.lower().startswith(("eval", "exec")) and not uses_request:
                continue
            lineno = text.count("\n", 0, m.start()) + 1
            reasons.append(f"{path}:{lineno} 안전하지 않은 역직렬화/동적 실행: {token.strip()}")
            evidence.append(f"{path}:{lineno}: {token.strip()}")
    if reasons:
        return _mk("insecure_deserialization", "안전하지 않은 역직렬화",
                   float(cfg.get("score_found", 0)), cfg,
                   passed=False, reasons=reasons, evidence=evidence)
    return _mk("insecure_deserialization", "안전하지 않은 역직렬화",
               float(cfg.get("score_clean", 100)), cfg,
               passed=True, reasons=[], evidence=[])


# A09 — security logging. Reward configured logging that records auth events.
_LOG_CONFIG = re.compile(r"""logging\.basicConfig|logging\.getLogger|app\.logger|dictConfig|RotatingFileHandler""")
_LOG_CALL = re.compile(r"""(?:logger|logging|app\.logger)\.(?:info|warning|error|exception|critical)\s*\(""")


def check_security_logging(sources: Sequence[Source], cfg: dict) -> CheckResult:
    joined = _joined(sources)
    configured = bool(_LOG_CONFIG.search(joined))
    logs_events = bool(_LOG_CALL.search(joined))
    if configured and logs_events:
        return _mk("security_logging", "보안 로깅", float(cfg.get("score_full", 100)),
                   cfg, passed=True, reasons=[], evidence=["logging 설정 + 이벤트 기록"])
    if configured or logs_events:
        return _mk("security_logging", "보안 로깅", float(cfg.get("score_partial", 50)),
                   cfg, passed=False, reasons=["로깅이 부분적으로만 구성됨(인증/오류 이벤트 기록 미흡)"],
                   evidence=[])
    return _mk("security_logging", "보안 로깅", float(cfg.get("score_none", 0)),
               cfg, passed=False,
               reasons=["보안 로깅/모니터링 구성이 없음 → 침해 탐지 불가"], evidence=[])


# A01 — SSRF sink (folded into Broken Access Control for 2025). Outbound fetch with a non-literal (possibly user) URL.
_OUTBOUND = re.compile(
    r"""(?:requests\.(?:get|post|put|delete|head|request)|httpx\.(?:get|post)|urllib\.request\.urlopen|urlopen)\s*\(\s*(?P<arg>[^,)\s]+)""",
    re.IGNORECASE,
)


def check_ssrf_sink(sources: Sequence[Source], cfg: dict) -> CheckResult:
    reasons: List[str] = []
    evidence: List[str] = []
    for path, text in sources:
        for m in _OUTBOUND.finditer(text):
            arg = m.group("arg").strip()
            if arg[:1] in ("'", '"'):
                continue  # literal/constant URL => not user-controlled
            lineno = text.count("\n", 0, m.start()) + 1
            reasons.append(f"{path}:{lineno} 사용자 제어 가능 URL로 외부 요청 → SSRF 가능: {arg}")
            evidence.append(f"{path}:{lineno}: {m.group(0)[:120]}")
    if reasons:
        return _mk("ssrf_sink", "SSRF", float(cfg.get("score_sink", 0)), cfg,
                   passed=False, reasons=reasons, evidence=evidence)
    # No outbound sink at all is the common (safe) case for a board app.
    return _mk("ssrf_sink", "SSRF", float(cfg.get("score_no_sink", 100)), cfg,
               passed=True, reasons=[], evidence=[])
