# Item 0 design draft — build once, start in ms (OpenStack)

## Re-measured 2026-10-30 19:55 on idle VM (load ~1.7), app #16, 5 runs each
- Today (pip at start): start→/posts answers 4.19 / 4.62 / 4.74 / 4.05 / 3.71 s (median 4.19).
- Deps image (pip at build, entrypoint without pip): 2.18 / 2.22 / 1.99 / 1.76 / 2.10 s (median 2.10). docker rm -f 1.1–1.5 s.
- Breakdown of the 2.1 s: `docker run -d` returns after 1.4–2.2 s; the app answers 0.32–0.39 s later. `docker run --rm python:3.11-slim true` alone takes 2.5–2.8 s. So on this VM the Docker daemon itself costs ~1.5–2 s per start (overlayfs, Docker 29.1.3, cgroup v2); pip is the other ~2 s.
- Deps image build for one requirements set: 41 s (legacy builder, cold pip cache).
- Conclusion: removing pip halves the start (4.2 → 2.1 s). No standby container (owner's decision 2026-10-30): start on click, about 2 s here.

## Facts measured earlier 2026-10-30 (VM busy building Kali, noisy)
- Today: entrypoint pip installs requirements on every start. App #16 (Flask==3.1.2) start→/posts answers: 4.08 / 3.62 / 3.59 s.
- Same app from a prebuilt per-app image: 2.40 / 2.29 / 2.97 s. docker rm -f: 1.7–2.2 s.
- Per-app image build (deps layer): 15.9 s.
- All 87 generated apps list only Flask (one pinned line). So a deps image keyed by requirements hash is shared by almost every app.
- All container starts go through one class: scoring/shared/sandbox.py Sandbox (grading, contract, preview, Kali target).

## Proposal
1. Deps image per requirements hash: `vibe-sec-deps:<sha256(requirements.txt + base image id)[:16]>`, FROM vibe-sec-sandbox, `RUN pip install -r requirements.txt` at build. Built right after harvest in codex_runner (generation phase), again only if requirements.txt changes during repair. Regrade of an old app: build on first use, then cached.
2. App code is NOT baked: still mounted read-only and copied to tmpfs as today (ms). So a repair round needs no rebuild unless requirements change.
3. entrypoint.sh: delete the pip install line. Boot = copy + exec python.
4. Sandbox picks the deps image; if the deps build failed, it runs the base image (Flask preinstalled) and the build log goes to boot_log — same non-fatal behavior as today.
5. Then remove the boot-grace hack (_wait_for_boot second wait) and the Kali per-replay `docker restart` re-running pip (review 24).
6. Kali: max_sessions 1, no standby. Click → start Kali and target from prebuilt images. Leave/io gap → `docker rm -f`. Files created disappear with the container ("딸깍 초기화"). The per-replay target `docker restart` stays (fresh DB per replay) but no longer re-runs pip.
7. Host tools and OSV DB: order in deploy/README.md becomes: apt + tools pinned → OSV DB download (dated snapshot) → docker build → start services. Nothing is installed after the image build, nothing at container start. OSV DB stays a pinned data snapshot, never refreshed during the event.
8. OpenStack: one VM one_prompt_main (m1.medium 4 vCPU/8GB, provider net 192.168.2.214, config drive). After setup, snapshot the whole server to Glance: `openstack server image create --name vibe-grader-<date> one_prompt_main` → recreate identically with `openstack server create --image vibe-grader-<date> --flavor m1.medium --network <provider> --config-drive True --key-name one_p ...`. No registry, Magnum or Zun needed.
9. Optional later: CI builds images and pushes to a registry; out of scope now.

## Capacity for 4 laptops + 1 Kali on 4 vCPU / 7.8GB
- scoring_concurrency 2 sandboxes (512m cap), preview max 4 (512m cap), Kali 1 (2g cap), generation concurrency 5 (codex CLI host processes + live preview), grader web+worker+postgres.
- Planned config: kali.max_sessions 1, preview.max_containers 4. Real memory use to be measured under load.
