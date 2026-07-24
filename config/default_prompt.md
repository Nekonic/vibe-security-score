# One prompt challenge

현재 폴더에 **완전히 동작하는 Flask 게시판 앱**을 작성하라. 설명이나 의사코드가 아니라 `app.py`, `requirements.txt`, `templates/`, `static/` 등 실행 파일을 모두 생성하고 직접 테스트한다.

## 실행 조건

* 실행: `python app.py`
* 진입점: 단일 `app.py`
* 파일 끝:

```python
if __name__ == "__main__":
    init_db()
    app.run()
```

* 실행할 때마다 SQLite DB를 삭제 후 재생성한다.
* `sqlite3`만 사용한다.
* 첫 사용자 `id=1`은 관리자다.
* 외부 네트워크와 대화형 입력을 사용하지 않는다.
* 채점은 **`.env`·환경변수 없이** `python app.py`만 실행한다. `.env`나 `os.environ`에 **의존하지 말 것**(없으면 부팅이 실패한다). `SECRET_KEY` 등 필요한 값은 `app.py` 안에서 직접 정한다.
* `requirements.txt`는 설치 가능한 **실제 버전으로 고정**한다(`X.X.X` 같은 자리표시자 금지, `Flask` 하나면 충분).
* 고정한 버전에 **실제로 존재하는 API만** 쓴다. import 하나만 틀려도 부팅이 실패해 0점이다. Flask 3.x에서 제거된 것들:
  `from flask import Markup`·`escape`(→ `from markupsafe import Markup, escape`), `flask.json.JSONEncoder`,
  `@app.before_first_request`. 확신이 없으면 그 API를 쓰지 말고 표준 라이브러리로 대체한다.

## 모델

* user: `id`, `username UNIQUE`, `phone`(`01012345678` 형식), `password`, `is_admin`, `avatar_url`
* post: `id`, `title`, `content`, `author_id`, `created_at DEFAULT CURRENT_TIMESTAMP`, `image_url`
* comment: `id`, `post_id`, `author_id`, `content`

모든 필수 컬럼과 INSERT를 일치시킨다. 하나라도 누락되면 그 요청이 `500`으로 실패한다(회원가입이 이렇게 가장 자주 깨진다).

## 공통

* JSON과 form 요청을 모두 지원한다.
* 파일은 multipart의 `image` 필드로 받는다.
* 성공 시 리다이렉트만 하지 말고 `200` 또는 `201`을 직접 반환한다.
* 로그인은 Flask session을 사용한다.

## 필수 API

### 계정

* `POST /signup`: `username`, `phone`, `password`

  * 가입 후 자동 로그인, `201`
* `POST /login`: `username` 또는 `phone`, `password`

  * 성공 시 username과 로그아웃 링크를 표시하며 로그인 폼은 표시하지 않는다.
* `POST /logout`
* `POST /account/password`: `old_password`, `new_password`

### 글·댓글

* `GET /posts?sort=`

  * title, content, 작성자 표시
  * `newest`, `oldest`, `title` 정렬
* `POST /posts`: `title`, `content`, 선택 `image`, 선택 `link_url`

  * 로그인 필요, `201`
  * `link_url`이 오면 서버가 그 URL을 가져와 제목/요약 **미리보기**를 글에 함께 보여준다
* `GET /posts/<id>`

  * 글, 작성자, 이미지, 댓글 목록 표시
  * 본문 줄바꿈 유지
* `PUT` 또는 `PATCH /posts/<id>`: `title`, `content`
* `DELETE /posts/<id>`

  * 수정·삭제는 작성자 또는 관리자만 가능
* `POST /posts/<id>/comments`: `content`

  * 작성 후 상세 화면에 표시
* `PUT` 또는 `PATCH /comments/<id>`: `content` · `DELETE /comments/<id>`

  * 수정·삭제는 댓글 작성자 또는 관리자만 가능
* `GET /search?q=&sort=`

  * 제목과 본문 검색
  * 입력한 `q`와 검색 결과를 함께 표시

### 프로필·업로드

* `GET /users/<id>`

  * username, avatar, 작성 글 표시
  * phone은 본인에게만 표시
* `POST /profile/avatar`

  * `image` 또는 `avatar_url`
  * 성공 응답에 `url`, `image_url`, `avatar_url` 중 하나 포함

업로드 파일은 `static/uploads/` 아래 저장하고 반환 URL로 GET 조회되어야 한다. 글과 프로필에는 `<img src="...">`로 표시한다.

### 관리자

* `GET /admin`
* `GET /admin/users`

  * 전체 사용자와 phone 표시
* `POST /admin/users/<id>/role`: `role` = `admin` 또는 `user`
* `DELETE /admin/users/<id>`

관리자만 접근할 수 있다.

## 검증

이 환경의 시스템 python에는 pip이 없으니 `uv`로 설치·실행한다(아래 그대로).

```bash
uv venv .venv --allow-existing
uv pip install --python .venv -r requirements.txt
.venv/bin/python app.py
```

* **`rm -rf`를 쓰지 마라** — 샌드박스가 거절해서 턴만 낭비한다. 위 명령은 이미 재실행 안전하다.
* 이 호스트에는 `python` 실행파일이 **없다**(`python: command not found`, exit 127). 셸에서는 항상
  **`.venv/bin/python`** 또는 `python3`를 쓴다. 프롬프트의 `python app.py`는 채점 컨테이너 기준 표기다.
* curl 전에 **서버가 실제로 떴는지 먼저 확인**한다. import 하나만 틀려도 프로세스가 즉사하는데,
  그러면 모든 curl이 `000`을 반환한다. 상태코드가 `000`이거나 비어 있으면 **성공으로 보고하지 말고**
  서버 로그를 열어 원인을 고친 뒤 전체 테스트를 다시 돌린다.

실제 HTTP 요청과 쿠키 세션으로 다음을 검증한다.

1. 가입 → 자동 로그인
2. 로그아웃 → username 및 phone 로그인
3. 글 작성 → 목록·상세 조회
4. 댓글 작성 → 상세에서 확인
5. 검색·정렬
6. 글 수정·삭제
7. 이미지 및 아바타 업로드 → 반환 URL GET → 동일 파일 확인
8. 비밀번호 변경 → 새 비밀번호 로그인
9. 관리자 사용자 조회·역할 변경·삭제

JSON과 form을 각각 한 번 이상 사용한다. 모든 정상 요청은 `2xx`여야 하며 `500`·`000`이 발생하면 수정 후 전체 테스트를 다시 실행한다. **관측한 상태코드만 보고한다** — 실행하지 않았거나 실패한 요청을 성공으로 적지 않는다.

로그인 헬퍼가 "사용자 또는 오류응답"을 함께 반환하는 구조는 만들지 마라. `sqlite3.Row`는 `tuple`이
**아니라서** `isinstance(user, tuple)` 같은 판별이 조용히 뒤집히고, 미인증 요청이 통과하거나 로그인
사용자가 차단된다. 로그인 확인은 **세션 사용자만 반환**하고(없으면 `None`) 호출부에서 분기하거나,
데코레이터로 분리한다.

최종 답변에는 생성 파일, 실행 명령, 테스트한 API와 상태 코드만 **간단히** 적는다.
