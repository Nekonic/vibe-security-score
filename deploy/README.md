# 프로덕션 배포 (Ubuntu)

실서버(Ubuntu)에 vibe-security-score를 올리는 절차. 채점기는 **네이티브로**
(systemd) 돌리고, 참가자 앱만 Docker 컨테이너로 띄운다 — 그래서 채점기 프로세스는
호스트 Docker 데몬에 접근할 수 있어야 한다(Docker-in-Docker 불필요).

구성 프로세스 2개:
- `vibe-grader-web` — gunicorn (참가자 UI + 운영자 `/admin`)
- `vibe-grader-worker` — 제출 파이프라인 (직렬 생성 → 병렬 채점; 시작 시 고아 자원 정리)

## 0. 사전 패키지

```bash
sudo apt update
sudo apt install -y docker.io postgresql nginx git curl
curl -LsSf https://astral.sh/uv/install.sh | sudo env UV_INSTALL_DIR=/usr/local/bin sh
```

## 1. 사용자 + 코드

```bash
sudo useradd -r -m -d /opt/vibe-security-score -s /bin/bash vibe
sudo usermod -aG docker vibe
sudo -u vibe git clone https://github.com/Nekonic/vibe-security-score.git /opt/vibe-security-score
cd /opt/vibe-security-score
```

## 2. 파이썬 환경 (uv)

```bash
sudo -u vibe uv sync --extra prod --no-dev
```

## 3. 샌드박스 이미지 빌드 (참가자 앱 실행용)

```bash
sudo -u vibe docker build -t vibe-sec-sandbox:latest sandbox/
```

## 3.5 채점 외부 도구 (필수)

기본 채점 모드는 `osv-scanner`·`gitleaks`·`semgrep`·`sqlmap`을 **요구**한다(하나라도 없으면
채점이 중단됨). 워커는 systemd로 돌아 기본 PATH만 보므로 **`/usr/local/bin`에 설치**한다.

```bash
sudo apt install -y golang-go pipx
sudo env GOBIN=/usr/local/bin go install github.com/google/osv-scanner/cmd/osv-scanner@latest
sudo env GOBIN=/usr/local/bin go install github.com/gitleaks/gitleaks/v8@latest
sudo pipx install --global semgrep && sudo pipx install --global sqlmap
# 확인 (워커와 같은 PATH에서 잡혀야 함)
for t in osv-scanner gitleaks semgrep sqlmap; do command -v "$t" || echo "MISSING: $t"; done
```
> 도구를 설치하지 않을 거라면 `config/scoring.yaml`의 `tools.*.enabled`를 끄거나 `--dev`
> 내장 검사로만 돌려야 하지만, **실채점에는 권장하지 않는다**.

## 4. PostgreSQL

```bash
sudo -u postgres psql <<'SQL'
CREATE USER vibe WITH PASSWORD 'CHANGE-ME';
CREATE DATABASE vibe_grader OWNER vibe;
SQL
```

## 5. 환경 파일

```bash
sudo cp deploy/vibe-grader.env.example /etc/vibe-grader.env
sudo chown vibe:vibe /etc/vibe-grader.env && sudo chmod 600 /etc/vibe-grader.env
sudoedit /etc/vibe-grader.env      # SECRET_KEY, ALLOWED_HOSTS, DB 비밀번호 등 수정
```
`DJANGO_SECRET_KEY` 생성: `python -c "import secrets; print(secrets.token_urlsafe(64))"`

## 6. DB 마이그레이션 · 정적 파일 · 관리자 계정

```bash
set -a && source /etc/vibe-grader.env && set +a
cd /opt/vibe-security-score/grader
sudo -u vibe --preserve-env uv run python manage.py migrate
sudo -u vibe --preserve-env uv run python manage.py collectstatic --noinput
sudo -u vibe --preserve-env uv run python manage.py createsuperuser
```

## 7. Codex 로그인 (코드 생성 인증)

`vibe` 사용자로, 환경 파일의 `CODEX_HOME` 아래에 로그인한다(과금 방지: API 키 아님).

```bash
sudo -u vibe CODEX_HOME=/opt/vibe-security-score/.codex codex login   # 헤드리스면 codex login --device-auth
sudo -u vibe CODEX_HOME=/opt/vibe-security-score/.codex codex --version
```
그런 다음 `config/scoring.yaml`의 `codex.model` / 플래그가 설치된 CLI와 맞는지 확인.

## 8. systemd 서비스

```bash
sudo cp deploy/systemd/vibe-grader-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vibe-grader-web vibe-grader-worker
systemctl status vibe-grader-web vibe-grader-worker
```

## 9. nginx + TLS

```bash
sudo cp deploy/nginx/vibe-grader.conf /etc/nginx/sites-available/vibe-grader
sudo ln -s /etc/nginx/sites-available/vibe-grader /etc/nginx/sites-enabled/
# server_name / static alias 경로를 실제 값으로 수정
sudo nginx -t && sudo systemctl reload nginx
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d grader.example.com          # 80 -> 443 자동 구성
```

## 10. 확인

```bash
curl -I https://grader.example.com/                 # 200
journalctl -u vibe-grader-worker -f                 # 워커 로그
```
웹 UI(`/`)에서 제출을 넣고 상태가 queued → generating → scoring → done 으로 흐르는지,
컨테이너가 남지 않는지(`docker ps -a`) 확인.

## 운영

- **로그**: `journalctl -u vibe-grader-web|worker`
- **설정 변경**(가중치/임계값 등): `config/scoring.yaml` 수정 후
  `sudo systemctl restart vibe-grader-worker` (채점 로직이 다시 읽음)
- **업데이트 배포**:
  ```bash
  cd /opt/vibe-security-score && sudo -u vibe git pull
  sudo -u vibe uv sync --extra prod --no-dev
  set -a && source /etc/vibe-grader.env && set +a
  cd grader && sudo -u vibe --preserve-env uv run python manage.py migrate
  sudo -u vibe --preserve-env uv run python manage.py collectstatic --noinput
  sudo systemctl restart vibe-grader-web vibe-grader-worker
  ```
- **Codex 세션 만료**: 워커가 감지해 `journalctl`에 `OPERATOR ALERT` 로그를 남긴다.
  `codex login`으로 재로그인한 뒤, 해당 제출을 **다시 제출**한다. (결과 페이지의 **재채점**은
  기존 생성 코드를 다시 채점할 뿐 Codex를 재호출하지 않으므로, 생성 자체가 실패해 코드가 없는
  제출은 재채점으로 복구되지 않는다.)
