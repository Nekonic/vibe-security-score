# vibe-security-score

부스용 **보안 코딩 챌린지 자동 채점기**. 참가자가 웹 UI에 프롬프트를 넣으면,
운영자의 ChatGPT(Codex CLI) 계정으로 Flask 게시판 앱을 생성하고, 그 코드를
격리 컨테이너에서 정적·동적으로 자동 채점해 점수/등급을 보여준다.
참가자는 코드를 직접 만지지 않는다.

## 구성 (4파트)

| 파트 | 위치 | 역할 |
|---|---|---|
| 1. 웹 UI | `grader/submissions/` (views·templates·admin) | 프롬프트 제출, 진행 폴링, 결과 화면, 운영자 대시보드 |
| 2. Codex 실행기 | `codex_runner/` | `codex exec`로 코드 생성 |
| 3. 채점 엔진 | `scoring/` | 정적(소스/의존성) + 동적(컨테이너 실공격) 분석 → 점수 |
| 4. 오케스트레이터 | `grader/submissions/orchestrator/` | 제출 큐, 직렬 생성 / 병렬 채점 파이프라인 |

- 채점기 = **Django**, 참가자 생성 앱 = **Flask**(채점 대상), 참가자 앱 실행 =
  **`python:3.11-slim` 격리 컨테이너**(비루트·자원제한·네트워크 유지).
- 모든 가중치·임계값·감점·게이트·도구 설정은 **`config/scoring.yaml`**.

## 요구 사항

- Python 3.11+, [uv](https://docs.astral.sh/uv/) (의존성 관리)
- Docker (동적 분석용) — 동적 분석 없이 정적만 돌릴 수도 있음
- Codex CLI + 운영자 ChatGPT(Pro) 로그인 — **코드 생성에만** 필요

## 설치 (개발)

```bash
# 1) 의존성 (uv가 .venv 생성 + 설치)
uv sync

# 2) 참가자 앱 실행용 샌드박스 이미지 빌드 (동적 분석에 필요)
docker build -t vibe-sec-sandbox:latest sandbox/

# 3) Django DB 준비
cd grader
uv run python manage.py migrate
uv run python manage.py createsuperuser   # 운영자 대시보드 로그인용
```

uv가 없다면 `curl -LsSf https://astral.sh/uv/install.sh | sh`

## 실행 (개발)

```bash
cd grader
uv run python manage.py runserver   # 참가자 UI: http://127.0.0.1:8000/  · 대시보드: /admin/
uv run python manage.py run_worker  # (별도 프로세스) 제출 처리: 생성→채점 (시작 시 고아 자원 정리)
```

## 프로덕션 (Ubuntu)

실서버 배포(uv + gunicorn + systemd + nginx + PostgreSQL)는
[deploy/README.md](deploy/README.md) 참고.

- 참가자: `/` 프롬프트 제출 → 진행·큐 위치 폴링 → 결과(항목별 ✔/✘·감점 사유·등급) · 순위 `/ranking/`.
- 운영자: `/admin/` 에서 전체 제출·상태·점수·큐 현황 확인, 실패 제출 재실행.

## 채점기만 단독으로 돌려보기 (Codex 없이)

일부러 취약하게 만든 샘플 앱으로 채점 파이프라인을 확인:

```bash
# 정적만 (Docker 불필요)
python -m scoring.cli static samples/vulnerable_board

# 정적 + 동적 (Docker 필요) — 하드코딩 시크릿·IDOR·XSS·SQLi·접근제어가 감점됨
python -m scoring.cli grade samples/vulnerable_board
```

## 테스트

```bash
uv run pytest scoring codex_runner            # 채점 엔진 + Codex 실행기 (63)
cd grader && uv run python manage.py test     # 웹 UI + 오케스트레이터 (17)
```

Codex 실제 생성 테스트(설치·로그인 시). **Windows는 WSL(Ubuntu) 안에서** 실행 —
Codex 샌드박스는 Linux/macOS만 지원(프로덕션 Ubuntu와 동일). codex와 smoke 모두 WSL
안에서 돌려야 한다(Windows용 codex를 WSL이 집으면 `node: not found`로 실패):

```bash
# WSL(Ubuntu/Debian) 안에서:
# 1) Node + codex 를 Linux 네이티브로 설치 (--include=optional 이 핵심:
#    플랫폼 바이너리 @openai/codex-linux-x64 가 optionalDependency 라 빠지면 실행 실패)
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt install -y nodejs
sudo npm install -g @openai/codex@latest --include=optional
which codex          # /usr/bin/codex 여야 함
codex login          # 헤드리스: codex login --device-auth
uv run python -m codex_runner.smoke
```

## 설정

- `config/scoring.yaml` — 가중치·임계값·감점·게이트 캡·등급 컷·컨테이너 제한·
  Codex 플래그·외부 도구·오케스트레이터 동시성/재시도. **로직에 하드코딩 없음.**
- `config/default_prompt.txt` — 참가자 입력창 기본 프롬프트.
- `data/` — 재현성용 로컬 고정 스냅샷(인기 패키지, OSV CVE).

## 운영자 주의 (과금·인증·재현성)

- **Codex 인증(OAuth) · 과금 방지**: 코드 생성은 API 키가 아니라 `codex login`으로
  로그인한 **운영자 ChatGPT 세션(OAuth)** 만 사용한다. 실행 시
  `OPENAI_API_KEY`/`CODEX_API_KEY`를 비운다(API 키 fallback 없음). dev 실제 생성
  테스트는 위 "테스트" 참고. 서버 배포·로그인은 [deploy/README.md](deploy/README.md).
- **Rate limit**: 생성은 5시간 롤링 한도를 공유하므로 **직렬 처리**된다.
  한도 초과 시 제출은 버려지지 않고 대기 후 재시도된다.
- **외부 도구(선택)**: `osv-scanner`, `sqlmap`, `gitleaks`, `semgrep` 이 있으면
  분석이 강화된다. 없으면 해당 검사는 "검사 생략" 처리되고, 점수는 동일하게 재현된다.
- **프로덕션(Ubuntu)**: `DJANGO_SECRET_KEY`, `DJANGO_DEBUG=0`,
  `DJANGO_ALLOWED_HOSTS` 설정. 병렬 채점 쓰기 때문에 DB는 **PostgreSQL** 권장
  (`DJANGO_DB_*`). 자세한 내용은 `grader/grader/settings.py` 주석 참고.

자세한 설계는 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 참고.
