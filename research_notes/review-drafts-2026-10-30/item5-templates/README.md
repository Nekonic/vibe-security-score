# 5번 고정 템플릿 시안

Codex는 `app.py`만 쓰고, 아래 `templates/`와 `static/board.js`는 우리가 준다. 시안이며 승인 전이다.

## 파일

| 파일 | 라우트 | app.py가 넘길 변수 |
|---|---|---|
| `templates/base.html` | 모든 화면의 틀 | `current_user` id·username·is_admin 또는 role, 선택 `csrf_token`, 선택 `message`·`error`, flash |
| `templates/_csrf.html` | 폼 안 include | `csrf_token` 문자열이나 함수. 없으면 출력 없음 |
| `templates/_post_item.html` | 목록 한 줄 include | `post` id·title·content·author·created_at |
| `templates/signup.html` | `GET /signup` → `POST /signup` | 없음 |
| `templates/login.html` | `GET /login?next=` → `POST /login` | `next` |
| `templates/posts.html` | `GET /posts?sort=`, 글쓰기 → `POST /posts` multipart | `posts`, `sort` |
| `templates/post_detail.html` | `GET /posts/<id>`, 댓글 → `POST /posts/<id>/comments`, 수정·삭제 → `PATCH`/`DELETE /posts/<id>`, `/comments/<id>` | `post` id·title·content·author·author_id·created_at·image_url·link_url·preview_title·preview_summary, `comments` id·content·author·author_id |
| `templates/search.html` | `GET /search?q=&sort=` | `q`, `posts`, `sort` |
| `templates/profile.html` | `GET /users/<id>`, 아바타 → `POST /profile/avatar` image 또는 avatar_url, 인증 → `POST /verify/request`, `POST /verify/confirm` code | `user` id·username·avatar_url·phone_verified·phone, `posts` |
| `templates/account_password.html` | `GET /account/password` → `POST /account/password` | 없음 |
| `templates/reset_request.html` | `GET /password/reset/request` → `POST /password/reset/request` | 없음 |
| `templates/reset.html` | `GET /password/reset?token=` → `POST /password/reset` | `token` |
| `templates/admin.html` | `GET /admin`, CSV 링크 `/admin/users.csv` | `user_count`, `post_count` |
| `templates/admin_users.html` | `GET /admin/users`, 역할 → `POST /admin/users/<id>/role` role, 삭제 → `DELETE /admin/users/<id>` | `users` id·username·phone·is_admin 또는 role |
| `templates/message.html` | 폼 요청 성공 때 200·201로 그림 | `message`, 선택 `next_url` |
| `templates/error.html` | 오류 화면 | `status`, `message` |
| `static/board.js` | PATCH·DELETE를 fetch로 보냄 | meta `csrf-token`을 `X-CSRFToken` 헤더로 |

- 필드 이름은 `scoring/contract/suite.py`·`client.py`가 보내는 것과 같다: username, phone, password, next, title, content, image, link_url, code, token, new_password, old_password, avatar_url, role, q, sort.
- 링크는 `url_for` 대신 계약 경로를 그대로 쓴다. app.py의 함수 이름을 묶지 않으려고.
- 변수는 dict, sqlite3.Row, 객체 모두 된다. Jinja가 `x.y`를 못 찾으면 `x['y']`로 찾는다.
- 계약에 없던 GET 화면 라우트 4개가 생긴다: `/signup`, `/account/password`, `/password/reset/request`, `/password/reset`. 프롬프트에 적어야 한다. 계약 검사는 이 라우트를 보지 않는다.

## 붙일 때 필요한 것 — 미구현

1. 생성 작업 디렉터리에 `templates/`, `static/board.js`, `static/bootstrap.min.css` 원본, 빈 `static/uploads/`를 미리 넣는다. 지금 `codex_runner/runner.py:545`는 빈 임시 디렉터리로 시작한다.
2. 수거 때 `templates/`와 `static/` 중 `uploads/`를 뺀 나머지를 우리 원본으로 덮어쓴다. 안 덮으면 Codex가 템플릿에 `|safe`를 넣어도 막을 수 없다.
3. `config/default_prompt.md`: `templates/`, `static/` 생성 지시를 빼고, 주어진 템플릿을 고치지 말라는 문장과 화면 GET 라우트 4개를 넣는다. 각 템플릿 머리의 `{# #}` 주석이 변수 목록이라 Codex가 읽을 수 있다.

## 확인한 것

- 저장소의 Flask로 16개 화면을 표본 데이터로 렌더하고, 채점기 정규식을 그대로 돌렸다. 검증 스크립트는 일회용이라 저장소에 넣지 않았다.
  - CSRF 토큰: 넘기면 `extract_csrf` 정규식이 같은 값을 찾고, 안 넘기면 아무것도 못 찾는다. 16개 모두.
  - `type="password"` 표시는 signup, login, account_password, reset 4개 화면에만 있다.
  - 관리자 마커는 admin, admin_users 2개 화면에만 걸린다. 오류·완료 화면은 안 걸린다.
  - XSS 표본은 글·댓글·검색어·아바타 모두 이스케이프됐다. `link_url=javascript:`는 href에 그대로 나온다. 의도한 것이다.
  - 상세의 `<img src>`, 목록의 `/posts/<id>`, 프로필 `<h1>username`, `/comments/<id>`를 계약 정규식이 찾는다.
  - 원본 템플릿 텍스트에 `xss_template`·`csp` 정적 검사가 걸리는 줄은 없다.
- 확인 안 함: 실제 생성 앱과 붙여 계약 30개를 돌린 것, 브라우저 화면, board.js 동작.
