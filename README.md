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
- **Docker — 채점의 기본 전제**(참가자 앱을 샌드박스 컨테이너로 실행)
- 외부 보안 도구(`osv-scanner`·`gitleaks`·`semgrep`·`sqlmap`) — 아래 참고
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

## 외부 보안 도구

`osv-scanner`·`gitleaks`·`semgrep`·`sqlmap`. **기본은 이 도구들이 설치돼 있어야 채점이 돌아간다**
(하나라도 없으면 에러로 중단). 설치 없이 내장 검사로 돌리려면 `--dev`(개발용, 권장 안 함).

```bash
# macOS
brew install go osv-scanner gitleaks semgrep sqlmap

# Linux
sudo apt install -y golang-go pipx
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
go install github.com/gitleaks/gitleaks/v8@latest
pipx install semgrep sqlmap
export PATH="$PATH:$(go env GOPATH)/bin"   # go install 바이너리 PATH 등록

# 설치 후 기본 채점(도구 사용)
python -m scoring.cli grade samples/vulnerable_board
# 설치 없이 내장 검사로만 돌릴 때(개발용)
python -m scoring.cli grade samples/vulnerable_board --dev
```

## 실행 (개발)

```bash
cd grader
uv run python manage.py runserver   # 참가자 UI: http://127.0.0.1:8000/  · 대시보드: /admin/
uv run python manage.py run_worker  # (별도 프로세스) 제출 처리: 생성→채점 (시작 시 고아 자원 정리)
```

## 프로덕션 (Ubuntu)

실서버 배포(uv + gunicorn + systemd + nginx + PostgreSQL)는
[deploy/README.md](deploy/README.md) 참고.

- 참가자: `/` 에서 **고정 시스템 프롬프트(좌) + 본인 프롬프트(우)** 제출(로그인 필요) →
  진행·큐 위치 폴링 → 결과(항목별 ✔/✘·감점 사유·등급).
- 운영자: `/admin/` 에서 전체 제출·상태·점수·큐 현황 확인, 결과 페이지에서 재채점(생성 코드 재평가).

## 접근 제어 (공개 배포)

**회원가입은 없다.** 페이지·진행/결과 화면은 로그인 없이 볼 수 있지만(부스 스크린에 그대로
띄우기 위함), **제출(=Codex 호출·과금)은 로그인해야만 가능**하다. 제출 폼/버튼은 로그인한
계정에게만 보이고, 익명의 제출 POST는 로그인으로 리다이렉트된다(랜덤 유입의 할당량 소모 차단).
계정은 운영자가 만든다. 세션은 로그인 후 **10시간** 유지, 비밀번호는 최소 12자 강제.

```bash
cd grader
# 운영자(관리·재채점 가능) 계정 = is_staff/superuser
uv run python manage.py createsuperuser
# 일반 제출 계정(노트북·스크린용)은 /admin/ → Operators → 추가, 또는 shell 로:
uv run python manage.py shell -c "from django.contrib.auth import get_user_model as G; \
G().objects.create_user(username='booth1', password='<매우-복잡한-비밀번호>')"
```

- **운영자(staff)**: 우측 상단 `이름 · 운영자` 표시 + `관리`(/admin/), 결과 페이지에 **재채점**
  버튼(기존 생성 코드를 Codex 재호출 없이 다시 채점 — scoring.yaml 바꾼 뒤 재평가에 유용).
  생성 코드가 없는 제출(생성 실패)은 재채점으로 복구되지 않으니 **재제출**해야 한다.
- **일반 계정**: 제출만 가능, 운영 버튼 없음.
- 순위(리더보드)는 로그인 없이 공개된다(`/ranking/`, 상단 `순위` 링크).

## 채점기만 단독으로 돌려보기 (Codex 없이)

커밋된 샘플 앱(실제 codex 생성물 복사본)으로 채점 파이프라인을 확인(외부 도구 설치 전제).
`vulnerable_board`는 방어가 얕은 앱(낮은 점수), `secure_board`는 거의 방어된 앱(높은 점수):

```bash
python -m scoring.cli static samples/vulnerable_board   # 정적만
python -m scoring.cli grade  samples/vulnerable_board   # 정적 + 동적(Docker 샌드박스)
python -m scoring.cli grade  samples/secure_board       # 하드닝 샘플(높은 점수 기대)
```

도구 미설치 환경이면 각 명령에 `--dev`를 붙여 내장 검사로 돌린다(개발용, 권장 안 함).

## 테스트

```bash
uv run pytest scoring codex_runner            # 채점 엔진 + Codex 실행기 (Docker 있으면 동적 통합 포함)
cd grader && uv run python manage.py test     # 웹 UI + 오케스트레이터
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
- `config/default_prompt.md` — **고정 시스템 프롬프트**(앱 스펙). 참가자는 별도 프롬프트를 작성하고,
  제출 시 `[시스템 프롬프트] + [참가자 프롬프트]`로 합쳐 Codex에 전달된다(`views._build_prompt`).
- `data/` — 재현성용 로컬 고정 스냅샷(인기 패키지, OSV CVE).

## 운영자 주의 (과금·인증·재현성)

- **Codex 인증(OAuth) · 과금 방지**: 코드 생성은 API 키가 아니라 `codex login`으로
  로그인한 **운영자 ChatGPT 세션(OAuth)** 만 사용한다. 실행 시
  `OPENAI_API_KEY`/`CODEX_API_KEY`를 비운다(API 키 fallback 없음). dev 실제 생성
  테스트는 위 "테스트" 참고. 서버 배포·로그인은 [deploy/README.md](deploy/README.md).
- **Rate limit**: 생성은 5시간 롤링 한도를 공유하므로 **직렬 처리**된다.
  한도 초과 시 제출은 버려지지 않고 대기 후 재시도된다.
- **외부 도구**: 기본 채점은 `osv-scanner`·`gitleaks`·`semgrep`·`sqlmap` 설치를 요구한다
  (미설치 시 중단). 내장 검사로 돌리는 `--dev`는 개발용이며 실제 채점엔 권장하지 않는다.
  설치는 위 "외부 보안 도구" 참고.
- **프로덕션(Ubuntu)**: `DJANGO_SECRET_KEY`, `DJANGO_DEBUG=0`,
  `DJANGO_ALLOWED_HOSTS` 설정. 병렬 채점 쓰기 때문에 DB는 **PostgreSQL** 권장
  (`DJANGO_DB_*`). 자세한 내용은 `grader/core/settings.py` 주석 참고.

자세한 설계는 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 참고.
