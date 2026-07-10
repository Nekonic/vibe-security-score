# Sandbox image for participant apps. Build: docker build -t vibe-sec-sandbox:latest sandbox/
# App dir mounts at /app; requirements install INSIDE this container only.
FROM python:3.11-slim

# Non-root (uid matches config sandbox.run_as_uid).
RUN useradd -u 10001 -m -s /usr/sbin/nologin runner

# Preinstall Flask so a broken requirements.txt still boots far enough to grade.
RUN pip install --no-cache-dir "Flask>=2,<4" "gunicorn>=21" && \
    mkdir -p /app && chown runner:runner /app

COPY --chown=root:root entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

# sitecustomize (on PYTHONPATH) forces 0.0.0.0 bind + no reloader for any Flask app.
COPY --chown=root:root sitecustomize.py /opt/boot/sitecustomize.py

USER runner
WORKDIR /app
EXPOSE 5000
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PYTHONPATH=/opt/boot APP_PORT=5000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
