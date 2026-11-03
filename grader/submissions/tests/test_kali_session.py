"""Kali session lifecycle without Docker: session ids, replacement, the io-gap reaper,
failed boots, and the orphan sweep (docker calls are faked)."""
from __future__ import annotations

import os
import subprocess
import threading
import time
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from submissions import kali_session as ks


def _done(*_a, **_k):
    return subprocess.CompletedProcess([], 0, "", "")


class KaliSessionTests(SimpleTestCase):
    def setUp(self):
        ks._SESSIONS.clear()
        self.docker = mock.patch.object(ks, "_docker", side_effect=_done).start()
        mock.patch.object(ks, "startup").start()
        # Boot is replaced by a stub that only records it ran.
        self.booted = []
        mock.patch.object(ks, "_boot", lambda sub, sess, cfg: self.booted.append(sess)).start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(ks._SESSIONS.clear)

    def _sub(self, pk):
        return SimpleNamespace(pk=pk, workdir="/nonexistent", findings=[])

    def _wait_teardowns(self):
        for t in threading.enumerate():
            if t is not threading.current_thread() and t.daemon and t.name != "kali-reaper":
                t.join(timeout=2)

    def test_start_returns_sid_and_io_needs_it(self):
        r = ks.start(self._sub(1))
        self.assertTrue(r["ok"] and r["sid"])
        self.assertTrue(ks.io(1, r["sid"], wait=0)["ok"])
        self.assertEqual(ks.io(1, "other", wait=0), {"ok": False, "alive": False})

    def test_start_again_replaces_the_session(self):
        first = ks.start(self._sub(1))["sid"]
        second = ks.start(self._sub(1))["sid"]
        self.assertNotEqual(first, second)
        self.assertFalse(ks.io(1, first, wait=0)["ok"])      # the old page stops polling
        self.assertTrue(ks.io(1, second, wait=0)["ok"])
        # An old page's stop beacon does not end the newer session.
        ks.stop(1, first)
        self.assertTrue(ks.io(1, second, wait=0)["ok"])
        ks.stop(1, second)
        self.assertFalse(ks.io(1, second, wait=0)["ok"])

    def test_names_are_unique_per_session(self):
        a = ks.start(self._sub(7))["sid"]
        run_a = ks.session(7, a).run
        b = ks.start(self._sub(7))["sid"]
        run_b = ks.session(7, b).run
        self.assertNotEqual(run_a, run_b)
        self.assertTrue(run_a.startswith(f"vibe-sec-kali-7-{os.getpid()}-"))

    def test_session_limit_counts_other_submissions(self):
        cfg = mock.Mock(get=lambda k, d=None: {"kali.max_sessions": 1}.get(k, d))
        with mock.patch.object(ks, "load_config", return_value=cfg):
            self.assertTrue(ks.start(self._sub(1))["ok"])
            self.assertFalse(ks.start(self._sub(2))["ok"])
            self.assertTrue(ks.start(self._sub(1))["ok"])        # same submission: replaced

    def test_reaper_removes_a_session_whose_page_stopped_polling(self):
        sid = ks.start(self._sub(1))["sid"]
        sess = ks.session(1, sid)
        self.assertEqual(ks.reap_once(now=sess.last_io + 1), [])
        self.assertEqual(ks.reap_once(now=sess.last_io + sess.io_gap + 0.1), [sess])
        self._wait_teardowns()
        self.assertTrue(sess.closed)
        self.assertIsNone(ks.session(1, sid))

    def test_reaper_keeps_unwatched_sessions(self):
        sid = ks.start(self._sub(1), watch_io=False)["sid"]
        sess = ks.session(1, sid)
        self.assertEqual(ks.reap_once(now=sess.last_io + 3600), [])

    def test_stop_wait_tears_down_synchronously(self):
        sid = ks.start(self._sub(1))["sid"]
        sess = ks.session(1, sid)
        self.docker.reset_mock()
        ks.stop(1, sid, wait=True)
        self.assertTrue(sess.closed)
        calls = [c.args[:3] for c in self.docker.call_args_list]
        self.assertIn(("ps", "-aq", "--filter"), calls)


class KaliBootFailureTests(SimpleTestCase):
    def setUp(self):
        ks._SESSIONS.clear()
        self.addCleanup(ks._SESSIONS.clear)

    def test_failed_boot_closes_the_session_and_removes_its_resources(self):
        box = mock.Mock(boot_failed=True, infra_error="boom", container_name="x")
        removed = []
        with mock.patch.object(ks, "Sandbox", return_value=box), \
             mock.patch.object(ks, "_remove_run", side_effect=removed.append):
            sess = ks.Session(pk=3)
            ks._SESSIONS[3] = sess
            ks._boot(SimpleNamespace(pk=3, workdir="/x", findings=[]), sess, mock.Mock(get=lambda k, d=None: d))
        self.assertTrue(sess.closed and not sess.ready)
        self.assertEqual(removed, [sess.run])
        out = ks.io(3, sess.sid, wait=0)
        self.assertTrue(out["ok"])
        self.assertFalse(out["alive"])                        # the page shows it and stops

    def test_stop_during_boot_stops_the_next_steps(self):
        box = mock.Mock(boot_failed=False, container_name="x")
        sess = ks.Session(pk=4)

        def enter():
            sess.closed = True                                # stop() arrived mid-boot
            return box
        box.__enter__ = mock.Mock(side_effect=enter)
        with mock.patch.object(ks, "Sandbox", return_value=box), \
             mock.patch.object(ks, "_docker", side_effect=_done) as docker, \
             mock.patch.object(ks, "SSRFCallback") as ssrf, \
             mock.patch.object(ks, "_remove_run") as rm:
            ks._boot(SimpleNamespace(pk=4, workdir="/x", findings=[]), sess, mock.Mock(get=lambda k, d=None: d))
        self.assertFalse(ssrf.called)
        self.assertFalse(any(c.args[:1] == ("run",) for c in docker.call_args_list))
        rm.assert_called_with(sess.run)


class KaliSweepTests(SimpleTestCase):
    def setUp(self):
        ks._SESSIONS.clear()
        self.addCleanup(ks._SESSIONS.clear)

    def test_sweep_removes_only_resources_no_live_process_owns(self):
        me = os.getpid()
        live = ks.Session(pk=1)
        ks._SESSIONS[1] = live
        dead_pid = 999_999_9
        names = [f"{live.run}", f"{live.run}-target", f"vibe-sec-kali-2-{dead_pid}-ab12cd34-target",
                 f"vibe-sec-kali-3-{me}-deadbeef", "vibe-sec-kali-9", "vibe-sec-kali-9-target",
                 "vibe-sec-kali-4-1-cafe0000-redir"]                 # pid 1 is alive
        nets = [f"{live.run}-net", f"vibe-sec-kali-2-{dead_pid}-ab12cd34-net", "vibe-sec-kali-9-net"]
        calls = []

        def docker(*args, **_k):
            calls.append(args)
            if args[:2] == ("ps", "-a"):
                return subprocess.CompletedProcess([], 0, "\n".join(names), "")
            if args[:2] == ("network", "ls"):
                return subprocess.CompletedProcess([], 0, "\n".join(nets), "")
            return _done()

        with mock.patch.object(ks, "_docker", side_effect=docker):
            ks.sweep_orphans()
        rm = next(c for c in calls if c[:2] == ("rm", "-f"))
        self.assertEqual(sorted(rm[2:]), sorted([f"vibe-sec-kali-2-{dead_pid}-ab12cd34-target",
                                                 f"vibe-sec-kali-3-{me}-deadbeef",
                                                 "vibe-sec-kali-9", "vibe-sec-kali-9-target"]))
        nrm = next(c for c in calls if c[:2] == ("network", "rm"))
        self.assertEqual(sorted(nrm[2:]), sorted([f"vibe-sec-kali-2-{dead_pid}-ab12cd34-net",
                                                  "vibe-sec-kali-9-net"]))


class PtyOwnershipTests(SimpleTestCase):
    def test_teardown_leaves_the_fd_to_the_pump(self):
        sess = ks.Session(pk=5)
        real_popen = subprocess.Popen

        def popen(argv, **kw):
            return real_popen(["sh", "-c", "while :; do echo x; sleep 0.01; done"], **kw)

        with mock.patch.object(ks.subprocess, "Popen", side_effect=popen), \
             mock.patch.object(ks, "_remove_run"):
            ks._open_shell(sess)
            fd = sess.master
            with mock.patch.object(ks.os, "close", wraps=os.close) as close:
                ks._teardown(sess)
                t = time.time()
                while sess.master is not None and time.time() - t < 5:
                    time.sleep(0.01)
        self.assertIsNone(sess.master)
        # Closed once, by the pump thread, not by teardown's thread.
        self.assertEqual([c.args for c in close.call_args_list if c.args == (fd,)], [(fd,)])
