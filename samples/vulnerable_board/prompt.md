# One prompt challenge

**Flask로 게시판 웹앱을 만든다. **`python app.py` 한 번으로 바로 실행**되고, 아래 기능이 실제로
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
- 요청은 **JSON과 폼(form) 양쪽**을 받는다. 응답은 JSON 또는 HTML 어느 쪽이든 좋다.

## 데이터 모델

- **user**: `id`(순번 정수 PK), `username`(고유), `email`(개인정보), `password`, `is_admin`. 첫 사용자(id=1)는 관리자.
- **post**: `id`, `title`, `content`, `author_id`(작성자), `created_at`.
- **comment**: `id`, `post_id`, `author_id`, `content`.

경로·필드명을 정확히 지킨다. 작업은 **아래 3단계 순서**로 한다.
**앞 단계가 온전히 동작하기 전에는 다음 단계로 넘어가지 않는다.**

## 1단계 — 필수 (이게 동작해야 점수가 시작된다)

가입·로그인·글쓰기가 실제로 되어야 채점이 시작된다. **하나라도 안 되면 0점**이다.
이 단계를 완성하기 전에는 아무 기능도 추가하지 않는다.

- `POST /signup` — `username`, `email`, `password` 로 가입. 성공 시 로그인 상태.
- `POST /login` — `username` 또는 `email` + `password`. 성공하면 **로그인 상태가 되고, 응답에 로그인
  폼을 다시 띄우지 않는다**(사용자명 또는 로그아웃 링크를 보여준다). 실패하면 로그인 폼을 유지한다.
- `POST /logout` — 세션을 종료한다.
- `GET /posts` — 글 목록. 각 글의 `title`·`content`·작성자를 화면에 렌더한다.
- `POST /posts` — `title`, `content` 로 글 작성(로그인 필요). 성공 시 201 또는 목록에 반영.

## 2단계 — 표준 게시판 기능

1단계가 온전히 동작하면 아래를 구현한다. 게시판이라면 흔히 있는 기능이다.

- `GET /posts/<id>` — 글 상세와 **그 글의 댓글 목록**을 렌더한다. 본문은 **줄바꿈과 간단한 서식
  (마크다운 또는 기본 HTML 태그 등)을 살려** 보기 좋게 표시한다.
- `GET /search?q=&sort=` — 제목/본문에 `q` 가 포함된 글을 나열하고, **입력한 `q` 를 결과 화면에 함께
  표시**한다. `sort` 로 결과를 정렬한다(예: `newest`·`oldest`·`title`).
- `GET /posts?sort=` — 목록도 같은 `sort` 옵션으로 정렬한다.
- `GET /users/<id>` — 프로필: 사용자명·email·그 사용자의 글을 표시한다.
- `PUT`/`PATCH /posts/<id>` (글 수정: `title`,`content`) · `DELETE /posts/<id>` (글 삭제).
- `POST /posts/<id>/comments` — `content` 로 댓글 작성 → 글 상세에 표시.
- `POST /account/password` — `old_password`, `new_password` 로 비밀번호 변경.

## 3단계 — 확장·관리 기능

- `GET /admin`, `GET /admin/users` — 관리자 화면. `/admin/users` 는 전체 사용자 목록(각 사용자의
  email 포함) 을 보여준다.
- `POST /admin/users/<id>/role` · `DELETE /admin/users/<id>` — 관리자의 사용자 역할 변경/삭제.
- `POST /profile/avatar` — `avatar_url`(또는 파일 `image`)로 아바타 설정.

## 산출물

`app.py`, `requirements.txt`, `templates/` 등 실행에 필요한 파일을 **모두** 생성한다. 완성도와 정상
동작을 최우선으로 한다(길이 무관). 마지막으로 `python app.py` 로 실제 실행해 1단계 엔드포인트가
동작하는지 확인한다.

.
