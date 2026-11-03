"""Grader-side SSRF callback listener.

A tiny HTTP server the dynamic SSRF probe hands to the graded app as a target URL.
If the app fetches it server-side, the request lands here and we record the token —
proof the server made an outbound request to an attacker-chosen PRIVATE/host address
(the listener is reached via the container's bridge gateway, a private range a proper
SSRF filter blocks). Records only; serves a trivial 200. Runs on a random free port
for the duration of one dynamic run.
"""
from __future__ import annotations

import http.server
import threading
from typing import Optional, Set


class _Handler(http.server.BaseHTTPRequestHandler):
    def _record(self) -> None:
        # token = first path segment, e.g. GET /ssrf-abc123/meta -> "ssrf-abc123"
        token = self.path.lstrip("/").split("/", 1)[0].split("?", 1)[0]
        if token:
            self.server.hits.add(token)  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = _record
    do_POST = _record
    do_HEAD = _record

    def log_message(self, *_args) -> None:  # silence stderr access log
        pass


class SSRFCallback:
    """Context manager: starts a background HTTP listener, exposes ``url_for`` /
    ``was_hit``. Never raises on start failure — ``port is None`` then and the probe
    treats a missing callback as 'undecidable' (skips — never accuses)."""

    def __init__(self) -> None:
        self._srv: Optional[http.server.ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.port: Optional[int] = None

    def __enter__(self) -> "SSRFCallback":
        try:
            srv = http.server.ThreadingHTTPServer(("0.0.0.0", 0), _Handler)
            srv.hits = set()  # type: ignore[attr-defined]
            self._srv = srv
            self.port = srv.server_address[1]
            self._thread = threading.Thread(target=srv.serve_forever, daemon=True)
            self._thread.start()
        except OSError:
            self._srv = None
            self.port = None
        return self

    def __exit__(self, *_exc) -> bool:
        if self._srv is not None:
            try:
                self._srv.shutdown()
                self._srv.server_close()
            except Exception:
                pass
        return False

    @property
    def hits(self) -> Set[str]:
        return self._srv.hits if self._srv is not None else set()  # type: ignore[attr-defined]

    def url_for(self, token: str, host: str) -> str:
        return f"http://{host}:{self.port}/{token}"

    def was_hit(self, token: str) -> bool:
        return token in self.hits


# ── Public-looking redirector (SSRF filter bypass via redirect) ─────────────
# A common "safe" preview resolves the URL's host, rejects private addresses — and
# then lets the HTTP client follow a 302 to a private address unchecked. To exercise
# that, the app must be handed a URL whose host is a PUBLIC address. A throwaway
# container on a dedicated docker network with a globally-routable-looking subnet
# plays the attacker's public host and 302s to the grader's private callback.
# It listens on port 80 (apps commonly allow only 80/443 in a preview URL) and also
# serves a plain public page, the positive control: a preview that renders its title
# fetches public URLs, so a silent private callback is a real defense. No internet
# needed, unlike an outside control page.
PUBLIC_PAGE_MARKER = "Grader Public Page"
_REDIRECTOR_CODE = r"""
import http.server, urllib.parse
PAGE = b"<!doctype html><html><head><title>%s</title><meta name='description' content='grader control page'></head><body>grader control page</body></html>"
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # like a real web server: an HTTP/1.0 reply closes the socket under clients that reuse it
    def do_GET(self):
        parts = urllib.parse.urlsplit(self.path)
        if parts.path == "/page":
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(PAGE))); self.end_headers()
            if self.command == "GET":
                self.wfile.write(PAGE)
            return
        to = urllib.parse.parse_qs(parts.query).get("to", [""])[0]
        self.send_response(302); self.send_header("Location", to)
        self.send_header("Content-Length", "0"); self.end_headers()
    do_HEAD = do_GET
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 80), H).serve_forever()
"""


class PublicRedirector:
    """Context manager around the redirector container. ``url_for(target)`` returns a
    URL on the public-looking host that 302s to ``target``; ``None`` when docker or
    the network can't be set up (the redirect probe then simply doesn't run)."""

    def __init__(self, image: str, network: str, subnet: str, container: str,
                 nonce: str = "", alias: str = "") -> None:
        self.image, self.network, self.subnet = image, network, subnet
        self.container = container
        self.ip: Optional[str] = None
        # A nonce in the page title proves a preview really fetched the page: no app
        # can know it otherwise (the contract's R18 uses this).
        self.page_title = f"{PUBLIC_PAGE_MARKER} {nonce}".strip()
        # A host name on the redirector's network (Docker's DNS answers it inside
        # the app container), for previews that refuse IP-address URLs. "{ip}" in it
        # is filled with an address picked for the container, so a name like
        # "p1.{ip}.nip.io" is also what public DNS answers for it.
        self.alias = alias

    def _docker(self, *args: str, timeout: float = 30):
        import subprocess
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)

    def __enter__(self) -> "PublicRedirector":
        try:
            if self._docker("network", "inspect", self.network).returncode != 0:
                self._docker("network", "create", "--subnet", self.subnet, self.network)
            run = None
            for ip in self._addresses():
                named = []
                if self.alias:
                    named = ["--network-alias", self.alias.format(ip=ip)] + (["--ip", ip] if ip else [])
                run = self._docker("run", "-d", "--rm", "--name", self.container, "--network", self.network,
                                   *named,
                                   "--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
                                   "--entrypoint", "python", self.image, "-c",
                                   _REDIRECTOR_CODE.replace("%s", self.page_title))
                if run.returncode == 0:
                    break
                self._docker("rm", "-f", self.container)  # a clash leaves a created container
            if run is not None and run.returncode == 0:
                if self.alias:
                    self.alias = self.alias.format(ip=ip)
                ip = self._docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                                  self.container).stdout.strip()
                self.ip = ip or None
        except Exception:
            self.ip = None
        return self

    def _addresses(self):
        """Addresses to try: Docker's own pick, or, for an alias naming the address,
        a few random ones in the upper half of the subnet (Docker hands out the
        lower half first, so concurrent redirectors rarely clash)."""
        if "{ip}" not in self.alias:
            return [""]
        import ipaddress
        import random
        hosts = list(ipaddress.ip_network(self.subnet).hosts())
        upper = hosts[len(hosts) // 2:]
        return [str(a) for a in random.sample(upper, min(5, len(upper)))]

    def attach(self, app_container: str) -> bool:
        """Give the app container a route to the redirector's network."""
        if self.ip is None:
            return False
        try:
            return self._docker("network", "connect", self.network, app_container).returncode == 0
        except Exception:
            return False

    def url_for(self, target: str) -> Optional[str]:
        if self.ip is None:
            return None
        from urllib.parse import quote
        return f"http://{self.ip}/r?to={quote(target, safe='')}"

    def page_url(self) -> Optional[str]:
        """The public control page (title ``page_title``)."""
        if self.ip is None:
            return None
        return f"http://{self.alias or self.ip}/page"

    def __exit__(self, *_exc) -> bool:
        try:
            self._docker("rm", "-f", self.container)
        except Exception:
            pass
        return False


def start_redirector(config, app_container: Optional[str], nonce: str = "",
                     alias: str = "") -> Optional[PublicRedirector]:
    """The public-looking redirector, attached to ``app_container``'s network (the
    caller attaches it later when None). None if disabled or docker can't set it up.
    The caller exits it."""
    import uuid
    rcfg = config.get("sandbox.ssrf_redirector", {}) or {}
    if not rcfg.get("enabled", True):
        return None
    prefix = str(config.get("orchestrator.container_name_prefix", "vibe-sec-dyn-"))
    red = PublicRedirector(
        image=str(config.get("sandbox.image", "vibe-sec-sandbox:latest")),
        network=str(rcfg.get("network", "vibe-sec-ssrfpub")),
        subnet=str(rcfg.get("subnet", "11.137.0.0/24")),
        container=f"{prefix}redir-{uuid.uuid4().hex[:10]}",
        nonce=nonce,
        alias=alias,
    ).__enter__()
    if red.ip is None or (app_container is not None and not red.attach(app_container)):
        red.__exit__(None, None, None)
        return None
    return red
