# vibe-security-score

*([English](README.md) | 한국어)*

생성형 AI(바이브코딩)로 만들어진 Flask 로그인/회원가입 앱의 보안성을 자동 채점하는 CLI 도구.

생성된 코드, `requirements.txt`, 그리고 참가자 프롬프트(`prompt.md`)가 모두 들어 있는 **제출
디렉터리 하나**를 입력받아 정적·동적 검사를 수행하고, **사람이 읽는 리포트(✔/✘ + 감점 사유)** 와
**기계용 JSON** 을 출력합니다.

```
submission/
├── app.py              # (또는 main.py / run.py / …) 생성된 Flask 앱
├── requirements.txt    # 앱 의존성
├── prompt.md           # 참가자 프롬프트
└── templates/ …        # 그 외 생성된 파일
```

## 요구 사항

채점기는 **Windows** 프로그램입니다. 아래 항목이 모두 설치·기동된 호스트를 전제로 합니다.

- **Windows + Python 3.11.**
- **Docker Desktop 실행 중.** functional 게이트가 제출물을 표준 Linux `python:3.11-slim`
  컨테이너로 기동하고, Windows 호스트에서 HTTP로 호출합니다.
- **`osv-scanner` 와 로컬 OSV 데이터베이스.** CVE 검사를 재현성을 위해 오프라인 모드로 실행합니다.
  설정은 [오프라인 CVE 데이터베이스](#오프라인-cve-데이터베이스) 참고.

## 동작 방식

채점기는 네 개의 모듈을 실행하며, 각 모듈은 부분점수(0–100)와 findings 목록을 반환합니다.

| 모듈 | 유형 | 검사 항목 |
| --- | --- | --- |
| `secure_coding` | 정적 | 하드코딩 시크릿, `debug=True`, CSRF, 비밀번호 해싱, raw SQL, XSS, 세션 쿠키 플래그, 보안 헤더 |
| `dependencies` | 정적 | CVE(OSV, 오프라인), 로컬 인기 패키지 스냅샷 기반 타이포스쿼팅 |
| `prompt_quality` | 정적 | 프롬프트의 보안 개념 커버리지·밀도 |
| `functional` | 동적 | 앱을 기동해 `POST /register` / `POST /login` 을 HTTP로 호출 |

functional 모듈은 제출물을 채점기가 통제하는 표준 `python:3.11-slim` 컨테이너로 기동합니다(참가자는
Dockerfile을 제공하지 않습니다). 채점기가 코드를 마운트하고 `requirements.txt`를 설치한 뒤 앱을
실행하고 HTTP로 호출합니다. 컨테이너는 네트워크를 유지하므로 앱이 DB를 쓰고 요청을 처리할 수 있습니다.

HTTP 계약은 고정(`POST /register`, `POST /login`)이지만 입출력은 관대하게 처리합니다: 가능하면
소스에서 필드명을 읽고, 안 되면 흔한 별칭 슈퍼셋을 전송합니다. 본문은 JSON으로 먼저 시도한 뒤 form으로
재시도하며, 2xx·3xx는 모두 성공으로 간주합니다.

## 사용법

```bash
# 의존성 설치
pip install -r requirements.txt

# 제출물 채점 — 사람용 리포트를 stdout으로 출력
# (프롬프트는 <제출 디렉터리>/prompt.md 에서 읽습니다)
python run.py --code path/to/submission

# 기계용 JSON을 파일로도 저장
python run.py --code path/to/submission --json result.json
```

번들된 샘플로 실행:

```bash
python run.py --code samples/insecure_app
python run.py --code samples/secure_app
```

## 채점 모델

- **최종 점수** = Σ(모듈 부분점수 × 가중치). 가중치는 `config.py`에 있습니다.
- functional 모듈은 **게이트**입니다: 앱이 기동하지 않거나 핵심 흐름(register/login)이 실패하면 최종
  점수가 `FUNCTIONAL_GATE_CAP`으로 제한됩니다. 빈·깨진 제출이 "취약점 0개"라는 이유로 만점을 받는
  것을 막습니다.
- 리포트는 각 검사를 ✔/✘ 와 감점 사유·부분점수로 나열한 뒤, 가중 합산·최종 점수·등급·PASS/FAIL을
  보여줍니다. 감점 사유가 핵심입니다 — 참가자에게 무엇을 고쳐야 하는지 알려줍니다.

모든 가중치·임계값·감점값은 `config.py`에 있으며, 모듈 로직은 이 값들을 하드코딩하지 않습니다.

## 테스트

```bash
python -m pytest -q
```

채점기 자체의 회귀 테스트이며, 제출물 채점용이 아닙니다. functional 게이트는 Docker/HTTP를 mock으로
처리해 검증합니다.

## 오프라인 CVE 데이터베이스

CVE 검사는 재현성을 위해 `osv-scanner`를 오프라인 모드로 실행합니다.

1. `osv-scanner`를 설치해 `PATH`에 둡니다.
2. `config.py`의 `OSV_OFFLINE_DB_DIR`(기본값 `data/osv_db/`)가 가리키는 디렉터리에 OSV DB 스냅샷을
   내려받습니다. 재현성을 위해 스냅샷을 고정하세요.

## 참고

- 앱 컨테이너는 포트를 Windows 호스트로 게시(`-p 5000:5000`)합니다. 읽기 전용
  shim(`docker_shim/sitecustomize.py`)을 마운트하고 `PYTHONPATH`에 올려 자동 로드시켜, 컨테이너
  안에서 Flask의 `app.run()`을 `0.0.0.0:5000`에 강제 바인딩합니다 — 그렇지 않으면 `127.0.0.1`에
  바인딩하는 앱은 게시된 포트로 도달할 수 없습니다. 컨테이너는 앱의 DB·외부 통신을 위해 네트워크를
  유지합니다.
- requirements.txt를 설치할 수 없거나 코드가 import 시 예외(없는 함수/가짜 API →
  ImportError/AttributeError)를 내는 제출물은 기동에 실패하여 functional 게이트를 통과하지 못합니다 —
  별도 분석기가 아니라 기동 시점에 걸러집니다.
