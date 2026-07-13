# vibe-security-score — 아키텍처

부스 게임: 참가자가 프롬프트를 작성 → 서버가 **Codex CLI**(운영자 ChatGPT 로그인)로
**Flask 게시판 앱**을 생성 → 채점기가 그 코드를 격리 컨테이너에서 자동 채점 → UI가
점수/등급을 표시. 참가자는 코드를 직접 만지지 않는다.

## 고정 스택 (혼동 금지)

| 관심사 | 기술 | 비고 |
|---|---|---|
| 채점기 웹 / 큐 / 대시보드 | **Django** (`grader/`, 프로젝트 패키지 `grader/core/`) | 운영자 서버. 채점 엔진 자체는 Django를 import하지 않음. |
| 참가자 생성 앱 | **Flask** | 채점 *대상*, Codex가 생성. |
| 참가자 앱 실행 | **`python:3.11-slim` 컨테이너** | 비루트(uid 10001), 메모리/CPU/pids 제한, 부팅 타임아웃. **네트워크는 켜둠.** |

채점기 호스트 환경과 참가자 Flask 환경은 **절대 공유되지 않는다**: 참가자
`requirements.txt`(취약·타이포스쿼팅 가능)는 **컨테이너 안에서만** 설치된다.

## 프롬프트 모델 (시스템 + 참가자)

Codex 프롬프트는 `submissions/views.py::_build_prompt`에서 두 부분으로 조립된다.

- **시스템 프롬프트** — `config/default_prompt.md`. **서버 측 고정** 스펙으로 앱 계약을
  정의(엔드포인트, `email` 포함 사용자 필드, `id=1` 관리자, 게시글 `title`/`content`).
  좌측 패널에 읽기 전용으로 렌더되며 참가자가 수정 불가.
- **참가자 프롬프트** — 참가자가 작성하는 자유 텍스트(우측 패널). 실제 채점 레버.

최종 프롬프트 = `시스템 프롬프트 + "\n\n" + 참가자 프롬프트`. 스펙을 서버 측에 고정하면
동적 프로브가 가정하는 앱 계약([APP_CONTRACT.md](APP_CONTRACT.md))을 참가자가 바꿀 수 없다.

## 네 파트

1. **웹 UI (Django, `grader/`)** — `Submission` 모델 + 상태 머신
   (`queued → generating → scoring → done | failed | rate_limited`), 모든 전이는
   `submissions/state.py`를 경유. 참가자 흐름: 두 패널 제출 → 상태·큐 위치 폴링
   (`status_json`) → 결과(항목별 ✔/✘ + 감점 사유 + 부분 점수 + 등급, `_category_groups`가 구성).
   공개 순위는 `/ranking/`(`views.leaderboard`, 로그인 없이 열람). **실시간 생성 뷰**가
   레닥션된 Codex 활동을 tail(`generation_events_json`). 운영자는 Django admin + 스태프 전용
   **재채점** 버튼. 운영자 계정은 커스텀 `accounts.Operator` 모델(이메일 컬럼 없음 — 이메일은
   참가자 앱 개념). Bootstrap UI는 오프라인 vendored.

2. **Codex 러너 (`codex_runner/`)** — `runner.generate`가 `codex exec`(비대화형)를 구동,
   프롬프트는 **stdin**으로 전달. 플래그 `--sandbox workspace-write --skip-git-repo-check
   --ephemeral --json --ignore-user-config --ignore-rules`. `app.py`/`requirements.txt`/
   `templates/`를 `data/generated/<id>/`로 하베스트하고 `prompt.md`를 기록. **ChatGPT 인증만** —
   `OPENAI_API_KEY`/`CODEX_API_KEY`를 비워 API 키 fallback 없음. `codex.model`이 비면 계정의
   기본 모델 사용(`gpt-5-codex` 같은 API 전용 id는 ChatGPT 계정 인증에서 거부됨). 직렬 사용
   (5시간 롤링 한도), 실행별 wall-clock 타임아웃이 프로세스 트리를 종료. JSONL 스트림은
   **실시간**으로 읽고(`event_sink`), `codex_runner/activity.py`가 각 이벤트를 **레닥션**
   (임시 작업경로·호스트 경로 제거, 명령 출력 제거)해 `events.jsonl`로 남긴다(결과 페이지가
   읽기 전용 tail). 원본 `transcript.json`은 운영자 전용.

3. **채점 엔진 (`scoring/`)** — 순수 Python(Django 무의존), 단독 테스트 가능.
   `grade.py::grade_submission` = 정적 + 동적 → `aggregate.combine_scores` → 리포트.
   흐름은 **단일 등록부(registry) → phase별 러너 → 취약점 컨트롤**로 정리돼 있다.

   - **등록부 (`registry.py`)** — 모든 정적 검사·동적 프로브를 `Control(id, label, phase, fn)`로
     **한 번씩** 선언(OWASP 패밀리 순서). `by_phase("static"|"dynamic")`로 필터.
   - **러너 (`runner.py`)**
     - `run_static` — 오프라인. `StaticContext`(sources·templates·requirements·app_dir·config)를
       모아 `registry.by_phase("static")`의 각 컨트롤을 실행.
     - `run_dynamic` — 컨테이너에 앱을 부팅(`shared.sandbox.Sandbox`)하고 `requests`로 공격.
       `functional`이 먼저 실행돼 게이트를 구동하고 세션/id를 시드(틀린 비밀번호 거부는 상태
       코드가 아니라 **인증 상태**로 판정 — 폼 앱은 실패 시 로그인 폼을 200으로 재렌더). 이어서
       나머지 프로브, 마지막에 `dependencies.resolved_cve`로 컨테이너 `pip freeze` 기준 전이 CVE를
       **재측정**. 판정 불가 검사는 0점이 아니라 **skip**(집계 제외). 타임아웃 전역 적용, teardown은
       `finally`.
   - **컨트롤 (`controls/`)** — OWASP 2025 패밀리별로 그 취약점의 **정적 검사 + 동적 프로브 + 등록**을
     한 파일에 둔다. A01 `access_control`(CSRF·SSRF·IDOR·관리자접근), A02 `misconfig`(debug·헤더·전송),
     A03 `dependencies`(CVE·타이포스쿼팅·전이 CVE), A04 `crypto`(시크릿·해싱·쿠키·세션위조),
     A05 `injection/sql`·`injection/xss`, A06 `design`(rate limiting), A07 `auth`(기능·약한 비번),
     A08 `integrity`(역직렬화), A09 `logging`, A10 `exceptions`(상세 오류), `sast`(semgrep, 리포트 전용).
   - **공용 (`shared/`)** — `http`(ProbeContext·Account·CSRF·응답 헬퍼), `sources`(소스 읽기·스캔),
     `sandbox`(컨테이너 수명주기), `external_tools`(osv/gitleaks/semgrep 실행), `sqlmap`.
   - **시그니처 분기** — 정적 컨트롤은 `fn(sctx, cfg)`(람다가 `StaticContext`를 실제 검사 인자로
     어댑트), 동적 프로브는 `fn(ctx, cfg)`. `functional`만 `fn(ctx, cfg, require) → (CheckResult,
     게이트bool)`로 특수 처리. 억지로 하나의 시그니처로 통일하지 않고 러너가 phase로 분기.

4. **오케스트레이터 (`grader/submissions/orchestrator/`)** — 워커 하나(`run_worker`):
   **직렬 생성**(전역 락 — 공유 ChatGPT 한도)이 **제한된 병렬 채점**(격리 컨테이너,
   `scoring_concurrency`)으로 이어진다. `process_one`이 **재채점 vs 생성**을 분기: `regrade_only`
   제출은 기존 `workdir`를 재채점하며 **Codex를 호출하지 않는다**(코드가 없으면 실패). 그 외에는
   생성 → 채점. 재시도/백오프; rate-limit은 실패가 아니라 재큐잉; 인증 실패는 재시도 폭주 없이
   전역 운영자 알림. 시작 시 1회 고아 자원 스윕(진행 중인 작업이 없어 안전)이 별도 청소기를 대체.

## 채점 계산

각 검사는 0–100. `aggregate.combine_scores`:

1. **카테고리 점수** = 해당 카테고리 검사들의 가중 평균(skip 검사 제외).
2. **최종** = 정규화된 카테고리 가중치로 가중, *존재하는* 카테고리에 대해 재정규화(정적 단독
   실행은 정적만으로 채점). 이 시점 값이 `raw_score`.
3. **치명 감점** (`_apply_critical_penalties`) — 실패한 **치명** 검사는 최종에서 고정 점수를
   *차감*(중첩, 0에서 바닥). 앱 전체를 노출시키는 결함은 평균으로 희석되지 않고 실점한다:

   | 검사 | 감점 | 검사 | 감점 |
   |---|---|---|---|
   | `sqli` | −25 | `weak_default_secret` | −15 |
   | `debug_true` | −20 | `reflected_xss` | −12 |
   | `access_control_admin` | −20 | `csrf_protection` | −6 |
   | `stored_xss` | −18 | | |

   `session_forgery`(weight 0)는 실증 증거를 `weak_default_secret`에 접어 넣는다(이중 계상 없음).
   각 감점은 결과 화면에 `severity` + `repro`를 동반.
4. **게이트 상한** (감점 *후* 적용되는 천장): 부팅 실패 → 상한 `0`; 기능 게이트 실패
   (회원가입/로그인/글작성) → 상한 `40`.

**등급 밴드** (최종 ≥ min, `grades`): `미흡 ≥0` · `통과 ≥60` · `우수 ≥80` · `최고 ≥95`.
PASS는 부팅/기능 실패가 없고 **그리고** 최종 ≥ 60. 보안 항목은 채점 전 비공개 — 결과 화면의
감점 사유로만 노출.

모든 가중치·임계값·감점·게이트 상한·등급 컷은 한 파일에 있다:
[`config/scoring.yaml`](../config/scoring.yaml) — **로직에 하드코딩 없음**. 8개 카테고리와
가중치(합 100)는 순수 config이며, 검사의 카테고리 재배치는 YAML 편집만으로 된다.

| 카테고리 | 가중치 | 카테고리 | 가중치 |
|---|---|---|---|
| `functional` | 20 | `xss` | 10 |
| `auth` | 15 | `security_config` | 10 |
| `sqli` | 15 | `dependencies` | 10 |
| `input_validation` | 10 | `ai_security` | 10 |

> 코드 위치(OWASP 패밀리, `controls/`)와 채점 버킷(`config` 카테고리)은 별개다. 집계는 파일
> 위치가 아니라 config 매핑을 따르므로 둘은 독립적이다.

## 샌드박스 (`sandbox/`)

`python:3.11-slim`, 비루트(uid 10001), 메모리/CPU/pids 제한, 네트워크 ON. `entrypoint.sh`가
앱을 쓰기 가능한 `/work` tmpfs로 복사하고 런타임 상태 파일(`*.sqlite3`/`*.db` 등)을 제거해
**매 채점을 clean state로** 시작한다(앱은 부팅 시 자체 DB를 새로 생성). `PYTHONPATH`의
`sitecustomize.py`가 `Flask.run`을 몽키패치해 `0.0.0.0:$APP_PORT`로 바인딩하고 reloader를 끈다
— 생성 앱은 흔히 `app.run(debug=True)`(127.0.0.1 바인딩 → Docker 포트맵으로 도달 불가)하므로.
`debug`는 유지해 디버그 페이지 취약점은 여전히 채점된다. `Sandbox.pip_freeze()`가 전이 CVE
재측정에 쓰인다.

## 저장소 레이아웃

```
config/scoring.yaml            # 단일 채점 설정
config/default_prompt.md       # 고정 시스템 프롬프트(앱 스펙)
scoring/                       # 채점 엔진 (순수 python)
  grade.py                     # 진입점: 정적+동적 → 집계 → 리포트
  runner.py                    # run_static / run_dynamic (registry를 phase로 실행)
  registry.py                  # 모든 컨트롤 단일 등록부 + by_phase()
  aggregate.py config.py models.py owasp.py cli.py
  controls/                    # OWASP 패밀리별 컨트롤 (정적검사 + 동적프로브 + 등록)
    base.py                    # Control 데이터클래스
    access_control(A01) misconfig(A02) dependencies(A03) crypto(A04)
    injection/{sql,xss}(A05) design(A06) auth(A07) integrity(A08) logging(A09) exceptions(A10) sast
  shared/                      # 공용: http(ProbeContext)·sources·sandbox·external_tools·sqlmap
codex_runner/                  # codex exec 래퍼 + 활동 레닥션 (+ smoke.py dev 테스트)
grader/                        # Django 프로젝트(패키지 grader/core/); 앱: submissions, accounts
  submissions/orchestrator/    # DB 큐 백엔드 + 파이프라인 (run_worker가 구동)
sandbox/                       # Dockerfile + entrypoint.sh + sitecustomize.py
samples/vulnerable_board/      # 방어 얕은 Flask 앱(debug/CSRF/헤더/약한 시크릿 결함) — 채점 픽스처
samples/secure_board/          # 하드닝 Flask 앱(CSRF·해싱·env 시크릿·헤더) — 채점 픽스처
data/                          # 생성 앱 + codex 트랜스크립트 + 고정 스냅샷(OSV, 인기 패키지)
deploy/                        # 프로덕션: gunicorn + systemd + nginx (deploy/README.md 참고)
pyproject.toml / uv.lock       # 의존성(uv)
```

## 환경

프로덕션 = Ubuntu, 의존성은 **uv**, 웹은 gunicorn + systemd(nginx 뒤), **PostgreSQL** DB
(병렬 채점 쓰기). 채점 도구(`osv-scanner`/`gitleaks`/`semgrep`/`sqlmap`)는 기본 모드에서 필수
(`--dev`는 내장 오프라인 검사로 대체 — 개발용). 배포 검증은 `samples/vulnerable_board/` 채점으로
(심어둔 `SECRET_KEY`, IDOR, 저장형 XSS, 관리자 접근, SQLi가 모두 실점해야 정상). 전체 배포는
[deploy/README.md](../deploy/README.md).
