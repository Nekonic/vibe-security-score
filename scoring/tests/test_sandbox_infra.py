"""A container docker could not start is an infrastructure failure to retry, never
the app failing to boot (which caps the score at 0). No Docker needed."""
from __future__ import annotations

from unittest import mock

import pytest

from scoring.config import load_config
from scoring.shared.sandbox import Sandbox, SandboxError


def _app(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n")
    return str(tmp_path)


def test_docker_run_failure_is_infra_not_boot(tmp_path):
    box = Sandbox(_app(tmp_path), load_config())
    with mock.patch.object(Sandbox, "_docker_run", side_effect=RuntimeError("port is already allocated")), \
         mock.patch.object(Sandbox, "_teardown"), mock.patch("scoring.shared.sandbox.time.sleep"):
        box.__enter__()
    assert box.boot_failed and "port is already allocated" in box.infra_error
    with pytest.raises(SandboxError):
        box.raise_if_infra_error()


def test_transient_docker_failure_is_retried(tmp_path):
    box = Sandbox(_app(tmp_path), load_config())
    calls = iter([RuntimeError("busy"), None])

    def run(_self, _src):
        err = next(calls)
        if err:
            raise err

    with mock.patch.object(Sandbox, "_docker_run", run), mock.patch.object(Sandbox, "_teardown"), \
         mock.patch.object(Sandbox, "_wait_for_boot", return_value=True), \
         mock.patch("scoring.shared.sandbox.time.sleep"):
        box.__enter__()
    assert not box.boot_failed
    box.raise_if_infra_error()  # recovered: nothing to raise


def test_missing_entrypoint_is_the_apps_boot_failure(tmp_path):
    box = Sandbox(str(tmp_path), load_config())
    box.__enter__()
    assert box.boot_failed and not box.infra_error
    box.raise_if_infra_error()  # the app's fault: scored, not retried


def test_app_boot_failure_after_a_docker_retry_is_the_apps(tmp_path):
    # The retry succeeded, so the first attempt's docker error no longer applies.
    box = Sandbox(_app(tmp_path), load_config())
    calls = iter([RuntimeError("busy"), None])

    def run(_self, _src):
        err = next(calls)
        if err:
            raise err

    with mock.patch.object(Sandbox, "_docker_run", run), mock.patch.object(Sandbox, "_teardown"), \
         mock.patch.object(Sandbox, "_poll_boot", return_value=False), \
         mock.patch.object(Sandbox, "_container_running", return_value=False), \
         mock.patch("scoring.shared.sandbox.time.sleep"):
        box.__enter__()
    assert box.boot_failed and not box.infra_error
    box.raise_if_infra_error()


def test_hung_boot_is_the_apps_after_one_app_boot(tmp_path):
    # Nothing is installed at start, so no second wait: a running container that
    # never answers within app_boot is the app's boot failure, polled once.
    box = Sandbox(_app(tmp_path), load_config())
    with mock.patch.object(Sandbox, "_docker_run"), mock.patch.object(Sandbox, "_teardown"), \
         mock.patch.object(Sandbox, "_poll_boot", return_value=False) as poll, \
         mock.patch.object(Sandbox, "_container_running", return_value=True):
        box.__enter__()
    assert box.boot_failed and not box.infra_error and poll.call_count == 1


def test_retry_uses_a_fresh_container_name(tmp_path):
    # A retry under the same name would collide with, or its teardown remove, a
    # container of that name it did not create.
    box = Sandbox(_app(tmp_path), load_config())
    box.container_name = "x-target"
    names, torn = [], []

    def run(self, _src):
        names.append(self.container_name)
        if len(names) == 1:
            raise RuntimeError("Conflict")

    with mock.patch.object(Sandbox, "_docker_run", run), \
         mock.patch.object(Sandbox, "_teardown", lambda self: torn.append(self.container_name)), \
         mock.patch.object(Sandbox, "_wait_for_boot", return_value=True), \
         mock.patch("scoring.shared.sandbox.time.sleep"):
        box.__enter__()
    assert names == ["x-target", "x-target-r1"] and torn == ["x-target"]
    assert box.container_name == "x-target-r1"
