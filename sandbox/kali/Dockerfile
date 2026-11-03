# Kali attack box: the booth's practice range (sandbox/kali/range.py) and the base
# of the PoC console's attack image (sandbox/attack/Dockerfile).
# Build: docker build -t vibe-sec-kali:latest sandbox/kali/
# A range puts this box and one generated app (`target`) on a private docker
# network; participants (or the pentest agent) attack http://target:5000 from here.
# The grader server is x86_64: build for it everywhere (local dev: colima x64 VM).
FROM --platform=linux/amd64 kalilinux/kali-rolling

ARG CODEX_VERSION=0.164.0
ENV DEBIAN_FRONTEND=noninteractive
# The http.kali.org redirector sometimes hands out an unreachable mirror mid-download;
# retry each package instead of failing the multi-GB install.
RUN echo 'Acquire::Retries "10";' > /etc/apt/apt.conf.d/80-retries

# CA certificates first, on their own: the base image has none, so any package the
# http.kali.org redirector serves from an HTTPS mirror fails "certificate verify failed".
RUN apt-get update && (apt-get install -y --no-install-recommends ca-certificates \
        || (sleep 5 && apt-get update && apt-get install -y --no-install-recommends ca-certificates))

# Kali's standard CLI toolset. The metapackage lists its tools as Recommends, so it
# is installed WITH recommends (nmap, sqlmap, nikto, hydra, john, metasploit, ...).
RUN apt-get update && apt-get install -y kali-linux-headless \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Web tools the headless set leaves out, Python for PoC scripts, Node for Codex CLI.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ffuf wfuzz dirb whatweb jq vim-tiny \
        python-is-python3 python3-requests python3-bs4 \
        nodejs npm \
    && npm install -g "@openai/codex@${CODEX_VERSION}" \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /root/.npm

COPY agent_prompt.md findings.schema.json /opt/range/
COPY motd /etc/motd
RUN echo 'cat /etc/motd' >> /root/.bashrc

WORKDIR /root
CMD ["sleep", "infinity"]
