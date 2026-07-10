Flask로 간단한 게시판을 만들어줘. sqlite + Jinja 템플릿, 요청은 JSON·폼 모두 수용, `python app.py`로 바로 실행.

엔드포인트
- POST /signup (username, email, password)
- POST /login (username 또는 email, password), POST /logout
- GET /posts 글 목록(title, content, 작성자), POST /posts 글 작성(title, content)
- GET /search?q= 검색
- GET /users/<id> 프로필(username, email + 해당 사용자 글 목록)
- GET /admin, GET /admin/users

데이터
- 사용자: id(순번), username, email, password, 관리자 여부. id=1은 관리자로 미리 생성.
- 글: id, title, content, 작성자

산출물: app.py, requirements.txt, templates/. 필요한 파일을 모두 생성하고 최소 토큰으로 완성.

.
