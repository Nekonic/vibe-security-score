# scoring/ — 보안 채점 엔진 구조

생성된 Flask 앱을 **정적(SAST) + 동적(DAST)** 으로 채점하는 순수 파이썬 라이브러리.
Django에 의존하지 않는다(웹 계층은 `grader/`가 이 라이브러리를 호출한다).

## 디렉터리

```
scoring/
  __init__.py      공개 API 재노출 — 외부는 여기와 config/models만 import 한다
  cli.py           CLI 진입점 (static / dynamic 서브커맨드)
  config.py        Config · load_config — YAML 설정 (외부 계약, leaf)
  models.py        결과 데이터클래스 + OWASP 태그 매핑 (leaf, 어휘)
  engine/          실행(동사): 입력 수집 → 검사 실행 → 집계 → 등급
    runner.py        run_static / run_dynamic — phase별 실행, 예외 래핑 소유
    aggregate.py     combine_scores — CheckResult → 카테고리 가중 집계
    grade.py         grade_submission / build_report — 파이프라인 최상위
    progress.py      실시간 진행률
  checks/          규칙(무엇): OWASP 패밀리별 검사 + 레지스트리
    __init__.py      CHECKS · by_phase — 모든 검사의 단일 선언·조립점
    base.py          Check · result · _undecidable · resolve_cfg — 검사 기반 코드
    A01_*.py … A10_*.py, sast.py   패밀리별 정적+동적 검사 (동거)
  shared/          배관(검사가 쓰는 도구): 검사가 의존하되 검사를 모른다
    http.py csrf.py sandbox.py external_tools.py sqlmap.py sources.py
  tests/
```

원칙: **디렉터리는 개념(동사=engine / 규칙=checks / 배관=shared)**, **root의 파일은
공개 표면(계약 + 진입점)** 이다. root에 계약(`config`·`models`)을 두는 이유는 외부
패키지(`grader/`, `codex_runner/`)가 `scoring.config` 경로로 직접 import 하기 때문 —
이 경로는 안정적이어야 한다.

## 계층 규칙 (import 방향은 한쪽으로만)

```
cli / __init__  →  engine  →  checks  →  shared  →  {config, models}
```

- `config`·`models`는 **leaf**: scoring 내부를 import 하지 않는다.
- `shared`는 `config`·`models`만 본다(검사·엔진을 모른다).
- `checks`는 `shared`·`base`를 쓴다. **engine·runner를 import 하지 않는다**(순환 방지 —
  검사에서 실행 컨텍스트가 필요하면 타입 없는 `ctx`로 받는다).
- `engine`이 `checks`·`shared`를 조립해 실행한다.

역방향 import가 필요해지면 계층이 틀린 것이다. 고쳐서 방향을 지킨다.

## 검사 추가법

새 검사는 해당 `checks/A0N_*.py`에 함수 하나와 `CHECKS` 항목 하나를 더할 뿐이다 —
`checks/__init__.py`가 자동으로 모은다. 러너·라벨·id 목록을 손대지 않는다.
검사 함수 규격은 [`../docs/CHECKS_CONVENTION.md`](../docs/CHECKS_CONVENTION.md).

```python
def check_new_thing(check, sctx, cfg):
    ...
    return result(check, cfg, score=..., passed=..., reasons=[...], evidence=[...])

CHECKS = [..., Check("new_thing", "새 검사", "static", check_new_thing)]
```

## 공개 API

외부(웹 계층·codex_runner)가 쓰는 것은 `scoring/__init__.py`가 재노출하는 것과
`scoring.config`뿐이다:

- `load_config` · `Config`
- `grade_submission` · `build_report`
- `combine_scores`
- `CheckResult` · `CategoryResult` · `GradeResult`

그 밖의 모듈(`engine.runner`, `checks`, `shared`)은 내부 구현이다.
