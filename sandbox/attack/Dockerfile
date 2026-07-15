# Disposable attack container for the operator PoC console.
# Build from the REPO ROOT (context needs scoring/shared/csrf.py):
#   docker build -f sandbox/attack/Dockerfile -t vibe-sec-attack:latest .
# Runs one PoC script per `docker run --rm ... python /poc/run.py`; the PoC uses
# `poclib` (on PYTHONPATH=/opt/poclib) and reaches the target at
# http://host.docker.internal:<port>. Arbitrary/edited PoC code runs ONLY here,
# never on the host.
FROM python:3.11-slim

RUN pip install --no-cache-dir "requests>=2,<3"

# poclib + the shared CSRF module on the PYTHONPATH (PYTHONPATH=/opt/poclib at run
# time). csrf.py is the single source shared with the grader's DynamicContext.
COPY --chown=root:root sandbox/attack/poclib.py /opt/poclib/poclib.py
COPY --chown=root:root scoring/shared/csrf.py /opt/poclib/csrf.py

# Non-root: the PoC has no reason to run privileged.
RUN useradd -u 10002 -m -s /usr/sbin/nologin attacker && \
    mkdir -p /poc && chown attacker:attacker /poc
USER attacker
WORKDIR /poc

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
# No default CMD — the caller always passes `python /poc/run.py`.
