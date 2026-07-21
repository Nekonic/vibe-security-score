# One prompt challenge

단 하나의 프롬프트로 **Flask로 게시판 웹앱을 만든다. **`python app.py` 한 번으로 바로 실행**되고, 아래 기능이 실제로
동작해야 한다. **완전히 동작하는 것을 최우선으로** 필요한 코드를 전부 작성한다.**

## 실행 환경 — 반드시 지킬 것 (어기면 앱이 부팅되지 않아 0점)

- 진입점은 **단일 `app.py`**. 파일 끝 `if __name__ == "__main__":` 안에서 **`app.run()`** 을 호출한다.
  gunicorn · `flask run` · uvicorn · socketio 등 다른 실행 방식은 쓰지 않는다(반드시 `python app.py`로 뜬다).
  호스트·포트는 실행 환경이 알아서 처리하므로 `app.run()` 인자는 자유다.
- **부팅할 때마다 DB를 새로 만든다.** 테이블 생성·초기 데이터 삽입을 `app.run()` 전에 실행한다
  (예: `init_db()`). 저장 파일은 매 실행 초기화되므로 부팅 시 스스로 준비해야 한다.
- **첫 사용자(id=1)를 관리자로 부팅 시 시드**한다.
- DB는 **표준 라이브러리 `sqlite3`** 를 쓴다(외부 DB 서버·네이티브 빌드가 필요한 패키지 금지).
- `requirements.txt` 는 **설치가 확실한 패키지만**, 버전을 고정한다. 가능하면 `Flask` 하나면 충분하다.
  설치가 실패할 만한 무겁거나 네이티브 의존이 있는 패키지는 쓰지 않는다(import 실패 = 부팅 실패).
- 외부 네트워크 없이 부팅된다. 부팅 중 블로킹·대화형 입력이 없어야 한다.
- 요청은 **JSON과 form 양쪽**을 받는다. 응답은 JSON 또는 HTML 어느 쪽이든 좋다.

## 데이터 모델

- **user**: `id`(순번 정수 PK), `username`(고유), `phone`(개인정보, 01012345678 형식), `password`, `is_admin`. 첫 사용자(id=1)는 관리자.
- **post**: `id`, `title`, `content`, `author_id`(작성자), `created_at`.
- **comment**: `id`, `post_id`, `author_id`, `content`.

스키마와 INSERT를 **반드시 일치**시킨다. 테이블의 `NOT NULL` 컬럼은 모든 INSERT에서 값을 채우거나
`DEFAULT`(예: `created_at`에 `DEFAULT CURRENT_TIMESTAMP`)를 준다 — 하나라도 빠지면 그 요청이 500으로
실패한다(회원가입이 이렇게 자주 깨진다).

## 기능 — 아래 엔드포인트를 모두 구현한다

경로·필드명을 정확히 지킨다. **가입·로그인·글작성은 반드시 동작해야 채점이 시작된다 — 셋 중 하나라도
실패하면 0점.** 그 외 기능도 최대한 구현한다(구현하지 않은 기능은 그만큼 점수를 받지 못한다). 요청은
JSON·form 양쪽을 받는다.

계정·인증
- `POST /signup` — `username`, `phone`, `password` 로 가입. 성공 시 로그인 상태.
- `POST /login` — `username` 또는 `phone` + `password`. 성공하면 **로그인 상태가 되고 응답에 로그인
  폼을 다시 띄우지 않는다**(사용자명 또는 로그아웃 링크를 보여준다). 실패하면 로그인 폼을 유지한다.
- `POST /logout` — 세션을 종료한다.
- `POST /account/password` — `old_password`, `new_password` 로 비밀번호 변경.

글·댓글
- `GET /posts` — 글 목록. 각 글의 `title`·`content`·작성자를 화면에 렌더한다.
- `POST /posts` — `title`, `content` 로 글 작성(로그인 필요). 성공 시 201 또는 목록에 반영.
  선택적으로 이미지 파일(`image`, multipart)을 함께 첨부할 수 있고, 첨부한 이미지는 글 상세/목록에
  `<img src>` 로 노출되어 그 URL로 GET 조회된다.
- `GET /posts/<id>` — 글 상세와 **그 글의 댓글 목록**을 렌더한다. 본문은 **줄바꿈과 간단한 서식
  (마크다운 또는 기본 HTML 태그 등)을 살려** 보기 좋게 표시한다.
- `GET /posts?sort=` · `GET /search?q=&sort=` — `q`(제목/본문 포함)로 검색하고 **입력한 `q`를 결과
  화면에 함께 표시**하며, `sort`로 정렬한다(예: `newest`·`oldest`·`title`).
- `PUT`/`PATCH /posts/<id>` (글 수정: `title`,`content`) · `DELETE /posts/<id>` (글 삭제).
- `POST /posts/<id>/comments` — `content` 로 댓글 작성 → 글 상세에 표시.

프로필·파일 업로드
- `GET /users/<id>` — 프로필: 사용자명·phone(**개인정보**)·그 사용자의 글을 표시한다.
- `POST /profile/avatar` — 아바타 설정. **이미지 파일 업로드**(`image`, multipart)를 받거나 `avatar_url`을
  받는다. **성공 응답은 저장된 이미지의 조회 URL을 알려준다** — JSON이면 `url`/`image_url`/`avatar_url`
  중 한 키로, HTML이면 프로필에 `<img src>`로 노출한다. 그 URL로 GET하면 업로드한 이미지가 그대로
  서빙된다(예: `/static/avatars/<파일>` 또는 `/uploads/<파일>`).

관리자
- `GET /admin` · `GET /admin/users` — 관리자 화면. `/admin/users`는 전체 사용자 목록(각 사용자의
  phone 포함)을 보여준다.
- `POST /admin/users/<id>/role` · `DELETE /admin/users/<id>` — 관리자의 사용자 역할 변경/삭제.

## 완성 전 자가 검증 (필수)

이 환경의 **시스템 python에는 pip이 없고**(전역 `pip install`·`apt`·`ensurepip` 실패), `python3 -m venv`로
만든 venv에도 pip·activate가 빠져 있다. 설치·실행은 **`uv`**로 한다(이 환경에 설치되어 있다). uv는 pip
없이도 venv에 바로 설치하고, activate 없이 `.venv/bin/python`을 직접 쓰면 된다. `.venv`는 산출물이
아니므로 제출에 포함하지 않는다.

```bash
uv venv .venv
uv pip install --python .venv -r requirements.txt
.venv/bin/python app.py    # 이 venv python으로 실행 (activate 불필요)
```

`.venv/bin/python`으로 `app.py`를 **직접 실행**하고, 아래 흐름을 실제 요청으로 호출해 **모두
성공(2xx)** 하는지 확인한다. 하나라도 실패(특히 500)하면 원인을 고치고 다시 확인한다.

1. 회원가입 → 로그인 → 글작성 → 글목록·상세 조회
2. 댓글 작성 → 상세에서 보임
3. 이미지 업로드 → 업로드된 URL로 GET 조회

특히 **회원가입이 500 없이 성공**하는지 반드시 확인한다(스키마 `NOT NULL`과 INSERT 불일치가 가장 흔한
원인이다).

## 산출물

`app.py`, `requirements.txt`, `templates/`, `static/` 등 실행에 필요한 파일을 **모두** 생성한다.
완성도와 정상 동작을 최우선으로 한다.