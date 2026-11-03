# 부스 VM 정전 대응

부스 VM `ubuntu@192.168.2.214`의 코드는 `~/app`, DB는 `~/app/grader/db.sqlite3`이다. 이 폴더의 파일로 VM이 다시 켜지면 서비스가 저절로 돌아온다.

| 파일 | 하는 일 |
|---|---|
| `vibe-web.service` | 웹 화면을 `runserver 0.0.0.0:8000 --insecure`로 띄운다. 꺼지면 3초 뒤 다시 켠다 |
| `vibe-grader.env.example` | 웹과 워커가 읽는 `/etc/vibe-grader.env`의 예시. DEBUG 끔, 비밀키, 허용 호스트 |
| `vibe-worker.service` | 제출 파이프라인을 돌린다. 켜질 때 하다 만 제출은 실패로 돌리고, 남은 샌드박스 컨테이너를 지운다 |
| `vibe-backup.timer`, `vibe-backup.service`, `backup.sh` | 매일 한국 시간 04:00에 DB와 `data/`를 `~/backups/<한국 날짜-시각>/`로 복사한다. 타이머에 Asia/Seoul을 적어 VM 시간대와 상관없다. 14일 지난 것은 지운다 |

## 도메인

`https://bcsc.aps.or.kr`는 Cloudflare를 거쳐 다른 서버의 nginx로 들어온다. 그 nginx가 HTTPS를 받고, `Host`를 그대로 둔 채 `http://192.168.2.214:8000`으로 넘긴다. `X-Forwarded-Proto`는 보내지 않는다. 그래서 `/etc/vibe-grader.env`에 아래가 들어 있다.

- `DJANGO_DEBUG=0`과 실제 비밀키. 공개 주소라 DEBUG가 켜져 있으면 오류 화면에 코드와 설정이 그대로 나온다. 2026-11-02에 끔.
- 접속 허용 호스트에 `bcsc.aps.or.kr`. 없으면 DisallowedHost 오류가 난다.
- 신뢰할 출처에 `https://bcsc.aps.or.kr`. 없으면 로그인 POST가 CSRF 403으로 막힌다. 측정함.
- `DJANGO_SECURE_SSL_REDIRECT=0`. Django는 요청을 http로 보므로 켜 두면 https로 다시 보내기를 끝없이 반복한다.

DEBUG를 끄면 세션과 CSRF 쿠키가 Secure가 된다. 그래서 로그인은 `https://bcsc.aps.or.kr`로만 된다. `http://192.168.2.214:8000`에서는 화면은 보이지만 브라우저가 쿠키를 저장하지 않아 로그인 POST가 403이 난다. 측정함.

## 설치

```bash
K=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
sed "s|^DJANGO_SECRET_KEY=.*|DJANGO_SECRET_KEY=$K|" ~/app/deploy/vm/vibe-grader.env.example | sudo install -m 600 /dev/stdin /etc/vibe-grader.env
sudo cp ~/app/deploy/vm/vibe-*.service ~/app/deploy/vm/vibe-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vibe-web vibe-worker vibe-backup.timer
```

2026-11-02에 설치하고 VM을 재부팅해 봤다. 약 25초 뒤 웹, 워커, docker, 타이머가 저절로 다시 켜졌고 Mac에서 `/ranking/`이 200이었다.

## 운영

- 상태 확인: `systemctl status vibe-web vibe-worker`
- 로그 보기: `journalctl -u vibe-worker -f`
- 재시작: `sudo systemctl restart vibe-worker`
- 워커를 손으로 kill하거나 nohup으로 띄우지 않는다. 손으로 띄우면 서비스와 워커가 두 개가 된다.

## 복구

DB는 정전 뒤 아래로 확인한다. `ok`가 아니면 서비스를 멈추고 백업으로 바꾼다.

```bash
~/app/.venv/bin/python -c "import sqlite3; print(sqlite3.connect('/home/ubuntu/app/grader/db.sqlite3').execute('PRAGMA integrity_check').fetchone()[0])"
```

백업으로 바꿀 때는 남은 저널 파일도 지운다. 남겨 두면 SQLite가 다음에 열 때 그 저널을 복원한 DB에 되감는다.

```bash
sudo systemctl stop vibe-web vibe-worker
rm -f ~/app/grader/db.sqlite3-journal ~/app/grader/db.sqlite3-wal ~/app/grader/db.sqlite3-shm
cp ~/backups/<날짜>/db.sqlite3 ~/app/grader/db.sqlite3
tar -C ~/app -xzf ~/backups/<날짜>/data.tgz
sudo systemctl start vibe-web vibe-worker
```

백업은 같은 VM 디스크에 있다. 디스크를 잃는 경우까지 대비하려면 `~/backups`를 다른 곳으로 옮겨야 한다.

## OpenStack 호스트

호스트 com01이 정전 뒤 다시 켜져도 nova는 기본값으로 인스턴스를 켜지 않는다. 옵션은 `[DEFAULT] resume_guests_state_on_host_boot`이고 기본값은 False다. nova 2025.2 설정 문서에서 확인했다. 배포 노드에서 아래를 설정한다.

`/etc/kolla/config/nova.conf`, 모든 nova 서비스에 적용:

```ini
[DEFAULT]
resume_guests_state_on_host_boot = true
```

```bash
kolla-ansible reconfigure -i INVENTORY
```

`INVENTORY`는 배포할 때 쓴 인벤토리 파일이다. 이 명령은 2025.2 문서에 있는 형식이고, 모든 서비스를 다시 설정한다.
