# 게시판 기능 명세 초안 (확정 전)

> **2026-10-25 실험으로 기각.** luna low로 직접 생성해 보니, 라우트 수는 기능 통과율에 차이가 없었다(99% vs 100%). 비밀글·포인트·프로필 수정은 5/5 앱이 기본으로 막았다. 자세한 내용은 `spec-experiment.md`.

근거: 같은 폴더의 `ai_failure_classes.md`(AI가 실제로 틀리는 취약점·프롬프트 민감도), `scenario_design_precedents.md`(도메인·기능 조합),
`spec_size_and_generation_cost.md`(엔드포인트 수 vs 기능 통과율), `../framework-recommendation/contract_test_loop_harness.md`(계약 루프).

## 원칙

1. **라우트 20개 → 15개.** 엔드포인트가 늘수록 약한 모델의 기능 통과율이 급락하고(AutoBaxBench, WebApp1K-Duo), 기능 게이트를 못 넘으면 보안 점수도 0이다. 기대 신호 = P(게이트 통과) × 보안 결정 수.
2. **기능은 "AI가 기본으로 틀리고, 참가자가 한 문장으로 고칠 수 있는" 결정을 만드는 것만 남긴다.** SQLi·XSS(Jinja autoescape)는 이미 대부분 맞히므로 차등이 작다.
3. **게시판 + 비밀글 + 포인트 혼합.** 순수 게시판은 모든 글이 공개라 인가(BOLA) 결정이 없다. 비밀글(라우트 0개 추가)과 포인트 송금(1개)로 AI가 가장 많이 놓치는 인가·비즈니스 로직 결정을 추가한다. 쇼핑몰 전체는 라우트가 두 배라 제외.
4. **계약 테스트(생성 루프가 통과시킬 테스트)는 기능만 본다.** "타인 접근 거부" 같은 보안 동작을 계약에 넣으면 루프가 모두에게 고쳐 줘서 차등이 사라진다.
5. 경로·필드 이름은 이 문서로 고정한다. 루프가 강제하므로 채점 프로브는 이름을 추측하지 않는다.

## 모델

| 테이블 | 컬럼 |
|---|---|
| user | `id`, `username UNIQUE`, `phone`, `password`, `role`(`user`/`admin`), `points INTEGER DEFAULT 100` |
| post | `id`, `title`, `content`, `author_id`, `created_at`, `image_url`, `link_url`, `is_private` |
| comment | `id`, `post_id`, `author_id`, `content` |

가장 먼저 가입한 사용자가 `admin`.

## 라우트 (15개)

| # | 라우트 | 기능 | 만들어지는 보안 결정 (근거 순위·출처) | 채점 오라클 |
|---|---|---|---|---|
| 1 | `POST /signup` | `username`, `phone`, `password` → 201, 자동 로그인 | Mass Assignment(`role`·`points`를 보내면?) · 비밀번호 정책 | 가입 후 `/admin/users` 접근·포인트 확인 |
| 2 | `POST /login` | `username` 또는 `phone` + `password` | **Rate Limiting** (#1: 14/15 앱 누락, 구체 지시로 0→4/5) | 실패 반복 후 정답 로그인 차단·지연 |
| 3 | `POST /logout` | 세션 종료 | 세션 무효화 · Session Timeout | 로그아웃 전 쿠키 재사용 |
| 4 | `GET /posts?q=&sort=` | 공개 글 목록, 제목·본문 검색, `newest`/`oldest`/`title` | Reflected XSS(검색어 표시) · SQLi(LIKE·ORDER BY) | 페이로드 반사, sqlmap |
| 5 | `POST /posts` | `title`, `content`, 선택 `image`(multipart), 선택 `link_url`, 선택 `is_private` → 201 | **CSRF** (#2: 15/15 누락) · File Upload(#7) · **SSRF**(#3: 링크 미리보기 5~6/6 취약) | 외부 출처 폼 POST, html/svg 업로드 서빙, 콜백 수신 |
| 6 | `GET /posts/<id>` | 글·작성자·이미지·링크 미리보기·댓글. 비밀글은 작성자와 관리자만 | **BOLA**(#4: 실서비스 감사 1위) · Stored XSS | 타인 비밀글 조회 |
| 7 | `PATCH /posts/<id>` | 작성자가 `title`, `content` 수정 | BOLA(수정) | 타인 글 수정 |
| 8 | `DELETE /posts/<id>` | 작성자가 삭제 | BOLA(삭제) | 타인 글 삭제 |
| 9 | `POST /posts/<id>/comments` | `content` → 201 | Stored XSS(댓글) | 페이로드 저장 후 렌더 |
| 10 | `GET /users/<id>` | username, 작성 글, points. 본인에게만 phone | 개인정보 노출(IDOR) | 타인 phone 노출 |
| 11 | `POST /profile` | 본인 `phone` 수정 | **Mass Assignment**(`role`/`points` 같이 보내면?) | 요청 후 role·points 변화 |
| 12 | `POST /points/send` | `to`(username), `amount` → 내 포인트 차감·상대 증가 | **비즈니스 로직**(#11: 음수·잔액 초과·자기 송금, 4/5 에이전트 미검증) | 음수 송금으로 내 잔액 증가 등 상태 재조회 |
| 13 | `GET /admin/users` | 관리자: 전체 사용자·phone | BFLA(관리자 기능 노출) · 기본 관리자 계정 | 일반 사용자 접근 |
| 14 | `POST /admin/users/<id>/role` | 관리자: `role` = `admin`/`user` | BFLA(스스로 승격) | 일반 사용자가 자기 role 변경 |
| 15 | `DELETE /admin/users/<id>` | 관리자: 사용자 삭제 | BFLA | 일반 사용자 삭제 시도 |

앱 전역 결정(라우트 없음): SECRET_KEY(`.env`), debug, 보안 헤더·쿠키 플래그, 에러 처리, 로깅, 의존성.

## 지금 명세에서 빠지는 것

| 빠지는 것 | 이유 |
|---|---|
| `POST /account/password` | 결정이 약하고(재인증), 라우트만 늘림. 세션 무효화는 로그아웃으로 확인 |
| `GET /search` | `GET /posts?q=`로 합침 |
| 댓글 수정·삭제 2개 | 글 수정·삭제와 같은 결정 반복 |
| `POST /profile/avatar` | 업로드는 글 이미지, URL 가져오기는 링크 미리보기와 중복 |
| `GET /admin` | `/admin/users`와 중복 |

## 계약 테스트(루프)에 들어가는 것 / 안 들어가는 것

- **들어감:** 각 라우트의 정상 동작. 2xx, 필드 반영, 본인 비밀글 조회, 송금 후 양쪽 잔액, 관리자 기능이 관리자에게 동작.
- **안 들어감:** 타인 접근 거부, 음수 금액 거부, role 무시, 로그인 제한 등 모든 보안 동작. 이것들이 채점 대상이다.

## 확정이 필요한 것

1. 혼합안(비밀글 + 포인트)으로 갈지, 순수 게시판 유지할지
2. 포인트 송금 대신 다른 값 기능(예: 추천·쿠폰)을 원하는지
3. 라우트 15개 수준이 괜찮은지(더 줄이면 #7·#15 후보)
