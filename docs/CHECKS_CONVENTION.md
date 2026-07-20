# scoring/checks 코딩 컨벤션

검사의 정체성(`id`·`label`·`phase`)은 `Check(...)`가, 입력은 `StaticContext`/`DynamicContext`가 이미
선언한다. **함수는 그것을 다시 쓰지 않는다.** 아래 원칙은 전부 이 한 줄에서 나온다.

`Check`의 필드: `id, label, phase, fn` + `cfg_path`(cfg가 사는 config 하위트리, 기본은 phase에서 파생)
· `report_only`(외부 SAST/시크릿 도구 — weight 0) · `standard`(기본 True; 러너가 표준 방식으로 호출).

## 골격

```python
"""A0N <패밀리명>: <정적 검사 + 동적 프로브 한 줄 요약>."""
from __future__ import annotations
# stdlib → requests → ..shared.* → .base

# ── <check_id>  (static | dynamic) ─────────────────────────────
_LOCAL_CONST = ...                     # 이 검사 전용, _ 접두, 함수 직상단
def check_<id>(check, sctx, cfg):
    ...

CHECKS = [ Check("<id>", "<label>", "<phase>", check_<id>), ... ]   # 항상 맨 끝
```

---

## 원칙 1 — 컨텍스트 객체 하나만 받는다

모든 검사 함수는 `(check, ctx, cfg)`. 필요한 값은 함수 안에서 꺼낸다. `CHECKS`엔 람다·로직 금지.

```python
# before — scoring/checks/A03_supply_chain.py
Check("cve", "의존성 CVE", "static", lambda sctx, cfg: check_cve(
    sctx.requirements, _pool_split(dict(sctx.config.static_dependencies), "cve"),
    sctx.requirements_path, sctx.config)),
```
```python
# after — 람다를 명명 어댑터로. 코어 check_cve(reqs, dep_cfg, ...)는 테스트와
#         dynamic_cve가 공유하므로 시그니처를 그대로 두고, 어댑터만 (check, sctx, cfg).
def _cve(check, sctx, cfg):
    dep_cfg = _pool_split(dict(sctx.config.static_dependencies), "cve")
    return check_cve(sctx.requirements, dep_cfg, sctx.requirements_path, sctx.config)

Check("cve", "의존성 CVE", "static", _cve),
```
근거: Long Parameter List / Introduce Parameter Object.

## 원칙 2 — 정체성은 `Check`에서 파생한다

`check_id`·`label`·`category`·`weight`를 함수 안에서 다시 쓰지 않는다. `category`는 `phase`가 결정한다.

```python
# before — scoring/checks/A02_security_misconfiguration.py
return CheckResult(
    check_id="debug_true", category="static", label="디버그 모드",
    score=score, weight=float(cfg.get("weight", 0)),
    passed=not reasons, penalty_reasons=reasons, evidence=evidence,
)
```
```python
# after
return result(check, cfg, score=score, passed=not reasons,
              reasons=reasons, evidence=evidence)
```

빌더 (scoring/checks/base.py):
```python
def result(check, cfg, *, score, passed, reasons=(), evidence=(), tool="", weight=None):
    return CheckResult(
        check_id=check.id, category=check.phase, label=check.label,
        score=_clamp(float(score)),                 # 클램프는 여기 한 곳
        weight=_weight(check, cfg, weight),          # report_only→0, override, else cfg["weight"]
        passed=passed, penalty_reasons=list(reasons), evidence=list(evidence), tool=tool,
    )
```

**cfg를 누가 찾나** — 러너가 `resolve_cfg(config, check)`로 넘긴다: `config[check.cfg_path][check.id]`.
`cfg_path`가 ""면 phase에서 파생(`static.checks` / `dynamic.checks`). 다른 곳에 사는 것만 명시한다
(외부 도구는 `cfg_path="tools", report_only=True`). **A03의 cve·typosquatting은 예외**: weight가
`static.dependencies` 풀(22점)을 `_pool_split`으로 나눈 값이라, 어댑터가 config를 직접 읽어 pool-split
dict를 코어에 넘긴다(러너 cfg를 그대로 쓰면 풀이 0이 된다).

## 원칙 3 — `CheckResult`는 한 가지 방식으로, 만든 뒤 고치지 않는다

`_mk`·위치인자를 폐기하고 `result(...)`로 통일한다. label이 다른 변종은 **별도 `Check`**로 선언한다.

```python
# before — 같은 것을 3가지로 (A01/A04/A02)
_mk("csrf_protection", "CSRF 보호", float(cfg.get("score_protected", 100)),
    cfg, passed=True, reasons=[], evidence=[hit.group(0)])
CheckResult("password_hashing", "static", "비밀번호 해싱", score_plain, ...)
CheckResult(check_id="debug_true", category="static", label="디버그 모드", ...)
```
```python
# after — 하나
result(check, cfg, score=..., passed=..., reasons=[...], evidence=[...])
```

**예외 — `dynamic_cve`는 그대로 둔다.** 레지스트리에 없고(러너가 지연을 줄이려 ThreadPool로 별도
호출), `check` 객체가 없어 `result()`를 못 쓴다. 게다가 Docker 없이는 검증 불가라 블라인드 리팩터링
하지 않는다 — 만든 뒤 `.tool`/`.label`을 세팅하는 코드를 의도적으로 유지한다. **검증 못 하는 코드는
"더 예쁘게"를 위해 건드리지 않는다.**

근거: Command–Query Separation.

## 원칙 4 — 가드절로 조기 반환하고, 한 함수는 한 추상화 수준

"판정 불가"·"도구 없음"은 맨 위 가드절에서 `_undecidable`로 반환한다(예외가 아니라 **의도된 판정**).
저수준 반복은 헬퍼로 내려, 검사 함수는 한 추상화 수준만 읽히게 한다.

```python
# before — scoring/checks/A06_insecure_design.py :: dynamic_rate_limiting
def dynamic_rate_limiting(ctx, cfg):
    weight = float(cfg.get("weight", 8)); label = "..."
    try:
        if ctx.userA is None:
            return _scored_zero("rate_limiting", label, weight, "테스트 계정 없음으로 판정 불가")
        attempts = int(cfg.get("attempts", 8)); blocked = False
        sess = requests.Session()
        for _ in range(attempts):
            r = ctx.post(sess, "/login", _login_payload(ctx.userA, "wrong-" + ...))
            if r is not None and (r.status_code in (429, 423) or any(...)):
                blocked = True; break
        if blocked: return CheckResult(...)
        return CheckResult(...)
    except Exception as exc:
        return _scored_zero("rate_limiting", label, weight, f"...예외: {exc}")
```
```python
# after
def dynamic_rate_limiting(check, ctx, cfg):
    if ctx.userA is None:
        return _undecidable(check, cfg, "테스트 계정 없음으로 판정 불가")   # 가드절
    attempts = int(cfg.get("attempts", 8))
    if _lockout_triggered(ctx, attempts):
        return result(check, cfg, score=cfg.get("score_present", 100), passed=True, evidence=[...])
    return result(check, cfg, score=cfg.get("score_missing", 0), passed=False, reasons=[...])

def _lockout_triggered(ctx, attempts) -> bool:      # 저수준 HTTP 반복은 아래로
    ...
```
근거: Guard Clauses / Single Level of Abstraction.

## 원칙 5 — 예외 래핑은 러너가 한다

프로브 본문엔 순수 로직만. `try/except`는 러너 한 곳.

```python
# scoring/engine/runner.py — 동적 루프, 호출·래핑이 여기 한 곳
elif c.standard:
    cfg = resolve_cfg(config, c)
    try:
        checks.append(c.fn(c, ctx, cfg))
    except Exception as exc:
        checks.append(_undecidable(c, cfg, f"{c.label} 프로브 예외: {exc}"))
```

`@probe` 데코레이터는 기각한다 — 붙이는 걸 깜빡하면 조용히 보호를 잃는다.

**opt-out은 `standard=False` 두 개뿐** (러너가 이들만 특별 호출):
- **`functional`** — 러너가 `require` 키를 주입해 부르고 `.passed`로 게이트 캡(40점 상한)을 구동한다.
  예외를 삼키면 채점기 버그가 참가자를 40점으로 상한시키므로 **전파**시킨다.
- **`sqli`** — `--dev` 밖에서 sqlmap이 못 돌면 `RuntimeError`를 **던진다**. 래퍼가 이를 `_undecidable`
  스킵으로 삼키면 안 되므로 루프 래핑에서 빠진다.
- **정적 단계 전체** — 정적 예외는 인프라 오류. 조용히 0점화하지 않고 전파한다.

근거: Symmetry(Kent Beck) — 단, 대칭이 해를 끼치면 이유를 적고 깬다.

## 원칙 6 — 호출자를 피호출자 위에 (Stepdown)

위에서 아래로 추상화가 한 단계씩 내려가게 배치한다. 검사별 상수는 함수 직상단에 둔다(응집).

```python
# before — scoring/checks/A01_broken_access_control.py
def _discover_user_id(ctx, acct): ...      # 헬퍼가 위
def dynamic_idor_profile(ctx, cfg): ...    # 호출자가 아래
```
```python
# after
def dynamic_idor_profile(check, ctx, cfg): ...   # 호출자가 위
def _discover_user_id(ctx, acct): ...            # 헬퍼가 아래
```
근거: Stepdown Rule.

## 원칙 7 — 이름은 집계 효과를 정직하게 말한다

표준 검사가 "판정 불가"를 반환할 땐 `_undecidable(check, cfg, reason)`을 쓴다. `skipped=True`라
`aggregate._weighted_avg`(`if not c.skipped`)가 **집계에서 제외**한다 — 이름이 그 사실을 말한다.

```python
# scoring/checks/base.py
def _undecidable(check, cfg, reason, *, passed=False, tool="", weight=None):
    return CheckResult(..., score=0.0, skipped=True,               # 0점이 아니라 제외
                       penalty_reasons=[f"검사 생략(판정 불가): {reason}"])
```

| 헬퍼 | 쓰임 | `passed` | 집계 |
|---|---|---|---|
| `_undecidable` | 표준 동적 검사의 판정 불가 | `False` | 제외 |
| `_skipped` (shared/external_tools.py) | 정적 도구 미설치/비활성 | `True` | 제외 |
| `_scored_zero` (shared/http.py) | `check` 객체가 없는 두 경로만(dynamic_cve 폴백·legacy sqli) | `False` | 제외 |

`_scored_zero`는 `_undecidable`의 구(舊) 형태다. `check`를 못 받는 위 두 곳에만 남았다 — 이름이
"0점"이라 거짓말하지만, 표준 경로로는 쓰지 않으니 확산되지 않는다.

## 안티-규칙

- 컨텍스트에 무관한 필드를 넣지 않는다(잡동사니 서랍).
- "인수 ≤3", "함수 ≤20줄" 같은 숫자를 목표로 삼지 않는다.
- 대칭을 위한 대칭을 만들지 않는다(원칙 5).
- 검증할 수 없는 코드(Docker 전용 등)를 "가독성"을 이유로 블라인드 리팩터링하지 않는다(원칙 3).
