"""Requirements go into a deps image built once; a container start installs nothing.
No Docker needed: docker calls are faked."""
from __future__ import annotations

import pathlib
import subprocess
from unittest import mock

import pytest

from scoring.config import load_config
from scoring.shared import deps_image
from scoring.shared.sandbox import Sandbox

_REPO = pathlib.Path(__file__).resolve().parents[2]
_BASE = str(load_config().get("sandbox.image"))


class _FakeDocker:
    """`docker image inspect` / `docker build` against an in-memory image store."""

    def __init__(self, build_ok=True):
        self.images = {_BASE: "sha256:base1"}
        self.builds = []
        self.build_ok = build_ok

    def __call__(self, argv, **_kw):
        if argv[:3] == ["docker", "image", "inspect"]:
            ref = argv[-1]
            ok = ref in self.images
            return subprocess.CompletedProcess(argv, 0 if ok else 1, self.images.get(ref, "") + "\n", "")
        if argv[:2] == ["docker", "build"]:
            tag = argv[argv.index("-t") + 1]
            self.builds.append(tag)
            if self.build_ok:
                self.images[tag] = "sha256:" + tag
                return subprocess.CompletedProcess(argv, 0, "Successfully tagged\n", "")
            return subprocess.CompletedProcess(argv, 1, "", "ERROR: No matching distribution found for nope==9\n")
        raise AssertionError(argv)


@pytest.fixture(autouse=True)
def _fresh_cache():
    deps_image._failed.clear()
    yield
    deps_image._failed.clear()


def _app(tmp_path, req="Flask==3.1.2\n"):
    (tmp_path / "app.py").write_text("print('hi')\n")
    if req is not None:
        (tmp_path / "requirements.txt").write_text(req)
    return str(tmp_path)


def test_builds_once_per_requirements_set(tmp_path):
    fake = _FakeDocker()
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    with mock.patch("scoring.shared.deps_image.subprocess.run", fake):
        img1, log1 = deps_image.ensure(_app(a), load_config())
        img2, log2 = deps_image.ensure(_app(b), load_config())  # same requirements
    assert img1 == img2 == deps_image.tag_for(b"Flask==3.1.2\n", "sha256:base1")
    assert img1.startswith("vibe-sec-deps:") and len(img1.split(":")[1]) == 16
    assert fake.builds == [img1] and log1 == log2 == ""


def test_tag_changes_with_requirements_and_base():
    t = deps_image.tag_for(b"Flask==3.1.2\n", "sha256:base1")
    assert t != deps_image.tag_for(b"Flask==3.1.3\n", "sha256:base1")
    assert t != deps_image.tag_for(b"Flask==3.1.2\n", "sha256:base2")


def test_no_requirements_runs_the_base_image(tmp_path):
    with mock.patch("scoring.shared.deps_image.subprocess.run", side_effect=AssertionError):
        assert deps_image.ensure(_app(tmp_path, req=None), load_config()) == (_BASE, "")


def test_failed_build_falls_back_to_base_with_log_and_is_not_retried(tmp_path):
    fake = _FakeDocker(build_ok=False)
    with mock.patch("scoring.shared.deps_image.subprocess.run", fake):
        img, log = deps_image.ensure(_app(tmp_path, "nope==9\n"), load_config())
        again = deps_image.ensure(_app(tmp_path, "nope==9\n"), load_config())
    assert img == _BASE and "No matching distribution" in log
    assert again == (img, log) and len(fake.builds) == 1


def test_failed_build_is_retried_after_a_while(tmp_path, monkeypatch):
    # A passing failure (PyPI down) must not stick for the worker's lifetime.
    fake = _FakeDocker(build_ok=False)
    now = [1000.0]
    monkeypatch.setattr(deps_image.time, "monotonic", lambda: now[0])
    with mock.patch("scoring.shared.deps_image.subprocess.run", fake):
        deps_image.ensure(_app(tmp_path, "nope==9\n"), load_config())
        now[0] += deps_image._RETRY_AFTER + 1
        fake.build_ok = True
        img, log = deps_image.ensure(_app(tmp_path, "nope==9\n"), load_config())
    assert img.startswith("vibe-sec-deps:") and log == "" and len(fake.builds) == 2


def test_sandbox_runs_the_deps_image_and_shows_a_failed_build_in_its_log(tmp_path):
    box = Sandbox(_app(tmp_path), load_config())
    runs = []

    def run(argv, **_kw):
        runs.append(argv)
        return subprocess.CompletedProcess(argv, 0, "app log\n", "")

    with mock.patch("scoring.shared.deps_image.ensure", return_value=("vibe-sec-base", "pip: boom")), \
         mock.patch("scoring.shared.sandbox.subprocess.run", run):
        box._docker_run(str(tmp_path))
        assert runs[-1][-1] == "vibe-sec-base"
        assert box.logs().startswith("[sandbox] 의존성 설치 실패\npip: boom\n")
        assert box.logs().endswith("app log\n")


def test_no_pip_install_at_container_start():
    assert "pip install" not in (_REPO / "sandbox" / "entrypoint.sh").read_text()
