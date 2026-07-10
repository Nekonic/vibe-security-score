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

산출물: app.py, requirements.txt, templates/. 등 필요한 파일을 모두 생성하고 최소 토큰으로 완성.

보안은 OWASP ASVS L1 이상과 OWASP Top 10을 만족하도록 구현.
입력 검증, 인증/인가, 세션, 오류 처리, 보안 헤더를 안전한 기본값으로 적용.
비밀번호는 강한 해시, SQL은 parameterized query만 사용.
SECRET_KEY는 환경변수에서 읽고 debug=False, 관리자 기능은 권한 검사를 필수 적용.
불필요한 설명 없이 최소 코드로 구현.
