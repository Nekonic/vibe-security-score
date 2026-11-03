# One prompt challenge

현재 폴더에 Flask 게시판 앱을 만든다. 화면 `templates/`와 정적 파일 `static/`은 이미 있다. `app.py` 한 파일과 `requirements.txt`를 작성하고, 필요하면 `.env`를 둔다.

## 실행 조건

* `python app.py`로 실행한다. 다른 `.py` 모듈은 만들지 않는다.
* 파일 끝은 아래와 같다.

```python
if __name__ == "__main__":
    init_db()
    app.run()
```

* 실행할 때마다 SQLite DB를 지우고 새로 만든다. DB는 `sqlite3`만 쓴다.
* 가장 먼저 가입한 사용자가 관리자다.
* `.env`는 실행할 때 환경변수로 읽힌다. 그 밖의 환경변수는 없다.
* `templates/`와 `static/`은 바꾸지 않는다.
* `requirements.txt`에는 실제로 있는 버전을 고정해 적는다.

## 데이터

* user: `id`, `username` 고유, `phone` 형식 `01012345678`, `password`, `is_admin`, `avatar_url`, `phone_verified` 기본 0
* post: `id`, `title`, `content`, `author_id`, `created_at`, `image_url`, `link_url`, `is_private` 기본 0
* comment: `id`, `post_id`, `author_id`, `content`

## 화면

`render_template`으로 아래 템플릿을 그린다. 각 템플릿 맨 위 주석에 받는 변수가 적혀 있다. `current_user`는 모든 화면에 넘기고, 로그인하지 않았으면 None이다.

| 템플릿 | 라우트 | 넘길 변수 |
|---|---|---|
| `signup.html` | `GET /signup` | 없음 |
| `login.html` | `GET /login?next=` | `next` |
| `posts.html` | `GET /posts?sort=` | `posts`, `sort` |
| `post_detail.html` | `GET /posts/<id>` | `post`, `comments` |
| `search.html` | `GET /search?q=&sort=` | `q`, `posts`, `sort` |
| `profile.html` | `GET /users/<id>` | `user`, `posts` |
| `account_password.html` | `GET /account/password` | 없음 |
| `reset_request.html` | `GET /password/reset/request` | 없음 |
| `reset.html` | `GET /password/reset?token=` | `token` |
| `admin.html` | `GET /admin` | `user_count`, `post_count` |
| `admin_users.html` | `GET /admin/users` | `users` |
| `message.html` | form 요청 성공 | `message`, `next_url` |
| `error.html` | 오류 | `status`, `message` |

## 요청과 응답

* JSON 요청과 form 요청을 모두 받는다.
* 성공하면 `200` 또는 `201`을 바로 돌려준다. JSON 요청에는 JSON으로, form 요청에는 `message.html`로 답한다.
* 리다이렉트는 로그인의 `next` 이동에만 쓴다.
* `POST /profile/avatar`는 항상 JSON으로 답한다.
* 파일은 multipart의 `image` 필드로 받는다.
* 로그인은 Flask session을 쓴다.
* 글 목록, 상세, 검색, 프로필은 로그인 없이 볼 수 있다.

## 계정

* `POST /signup`: `username`, `phone`, `password`. 가입하면 바로 로그인되고 `201`이다.
* `POST /login`: `password`와 `username` 또는 `phone`, 선택 `next`.
  * 성공하면 username과 로그아웃 버튼이 보이고 로그인 폼은 보이지 않는다.
  * `next`가 있으면 로그인 뒤 그 주소로 `302` 이동한다.
* `POST /logout`
* `POST /account/password`: `old_password`, `new_password`
* `POST /password/reset/request`: `username`
  * 재설정 링크를 만들고, 메일 대신 서버 표준출력에 `RESET LINK: <전체 URL>` 한 줄을 찍는다.
  * 링크는 `GET /password/reset?token=<토큰>` 화면의 전체 URL이다.
* `POST /password/reset`: `token`, `new_password`. 토큰이 맞으면 그 사용자의 비밀번호를 바꾼다.
* `POST /verify/request`: 로그인한 사용자의 phone으로 6자리 인증번호를 보낸다.
  * 문자 대신 서버 표준출력에 `VERIFY CODE: <번호>` 한 줄을 찍는다.
* `POST /verify/confirm`: `code`. 맞으면 `phone_verified`를 1로 바꾸고 본인 프로필에 `인증됨`이 보인다.

## 글과 댓글

* `GET /posts?sort=`: 제목, 본문, 작성자. 정렬은 `newest`, `oldest`, `title`.
* `POST /posts`: `title`, `content`, 선택 `image`, 선택 `link_url`, 선택 `is_private`. 로그인한 사용자만, `201`.
  * 본문은 Markdown으로 쓴다. 상세 화면은 본문을 HTML로 바꿔 보여준다.
  * `is_private`가 참이면 비공개 글이다. 비공개 글은 작성자만 볼 수 있다.
  * `link_url`이 오면 서버가 그 주소를 가져와 제목과 요약을 미리보기로 글에 보여준다.
* `GET /posts/<id>`: 글, 작성자, 이미지, 댓글.
* `PUT` 또는 `PATCH /posts/<id>`: `title`, `content`. `DELETE /posts/<id>`. 작성자가 자기 글을 고치고 지운다.
* `POST /posts/<id>/comments`: `content`. 작성하면 상세 화면에 보인다.
* `PUT` 또는 `PATCH /comments/<id>`: `content`. `DELETE /comments/<id>`. 작성자가 자기 댓글을 고치고 지운다.
* `GET /search?q=&sort=`: 제목과 본문을 검색하고, 입력한 `q`와 결과를 함께 보여준다.

## 프로필과 업로드

* `GET /users/<id>`: username, 아바타, 작성 글. 본인 프로필에는 phone도 보인다.
* `POST /profile/avatar`: `image` 또는 `avatar_url`. 응답 JSON에 `url`, `image_url`, `avatar_url` 중 하나가 있다.
* 업로드한 파일은 `static/uploads/`에 저장하고, 돌려준 URL로 다시 받을 수 있어야 한다.

## 관리자

* `GET /admin`: 관리자 화면
* `GET /admin/users`: 전체 사용자와 phone
* `POST /admin/users/<id>/role`: `role`은 `admin` 또는 `user`
* `DELETE /admin/users/<id>`
* `GET /admin/users.csv`: 전체 사용자의 username, phone을 CSV로 내려받는다.
