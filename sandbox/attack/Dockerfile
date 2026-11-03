# Kali box for the operator attack demonstration: the full Kali toolset
# (sandbox/kali) plus the grader's own scoring code, so `python <check>.py` replays
# the exact probes a grade came from (sandbox/attack/kali_poc.py).
# Build the Kali image first, then this one from the REPO ROOT:
#   docker build -t vibe-sec-kali:latest sandbox/kali/
#   docker build -f sandbox/attack/Dockerfile -t vibe-sec-attack:latest .
# The grader server is x86_64: build for it everywhere (local dev: colima x64 VM).
ARG UV_VERSION=0.13.6
FROM --platform=linux/amd64 ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

FROM --platform=linux/amd64 vibe-sec-kali:latest

# The grader's Python (3.12), exact dependencies (uv.lock) and sqlmap version in a
# venv of their own, so replayed probes behave as in grading. The venv is NOT put on
# PATH and no PYTHONPATH is set: Kali's tools keep the system Python, and kali_poc.py
# re-runs itself with the venv's python, venv bin first on PATH for that process
# only (the pinned sqlmap). Keep these equal to the grader server
# (deploy/README.md). uv comes from its pinned image: Kali's own pip is not relied on.
ARG PYTHON_VERSION=3.12
ARG SQLMAP_VERSION=1.10.10
COPY --from=uv /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock /opt/vibe/
RUN cd /opt/vibe && uv export --frozen --no-dev --no-hashes --no-emit-project -o /tmp/req.txt \
    && uv venv --python "${PYTHON_VERSION}" /opt/vibe/.venv \
    && uv pip install --python /opt/vibe/.venv/bin/python -r /tmp/req.txt "sqlmap==${SQLMAP_VERSION}" \
    && rm -rf /tmp/req.txt /root/.cache

COPY scoring /opt/vibe/scoring
COPY config/scoring.yaml /opt/vibe/config/scoring.yaml
COPY sandbox/attack/kali_poc.py /opt/vibe/kali_poc.py
# The per-check scripts in ~/poc `import kali_poc`; their own folder is on sys.path.
RUN mkdir -p /root/poc && ln -s /opt/vibe/kali_poc.py /root/poc/kali_poc.py

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /root/poc
CMD ["sleep", "infinity"]
