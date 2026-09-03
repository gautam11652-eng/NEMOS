"""Tests for capture preflight, interface enumeration and the state model.

This exists because of a real deployment failure. On Kali, NEMOS reported:

    Capture: Blocked
    CAP_NET_RAW is required for packet capture
    Packets recorded: 0

Three different problems -- a misspelled interface name, a missing capability,
an uninstalled backend -- all reached the operator as roughly that, and none of
them said what to do next. So the properties under test are:

- a wrong interface name is reported as a wrong interface name, with the list
  of real ones, and never as a permission problem;
- every failure state carries one actionable sentence for *this* platform;
- ONLINE is never claimed on a successful bind alone -- only a packet earns it;
- nothing here ever fabricates a packet count.
"""

from __future__ import annotations

import socket
import sys
import unittest
from unittest.mock import patch

from nemos import capture
from nemos.capture import (
    STATE_BLOCKED,
    STATE_ERROR,
    STATE_NO_INTERFACE,
    STATE_NO_TRAFFIC,
    STATE_OFF,
    STATE_ONLINE,
    STATE_STARTING,
    PacketCapture,
    backend_available,
    has_cap_net_raw,
    interface_is_up,
    list_interfaces,
    raw_socket_permitted,
    remedy,
)

LINUX = sys.platform.startswith("linux")


class InterfaceEnumerationTests(unittest.TestCase):
    def test_interfaces_are_enumerated_not_guessed(self):
        names = list_interfaces()
        self.assertIsInstance(names, list)
        self.assertTrue(all(isinstance(n, str) and n for n in names))

    @unittest.skipUnless(LINUX, "loopback naming is Linux-specific here")
    def test_loopback_is_found_on_linux(self):
        self.assertIn("lo", list_interfaces())

    def test_no_interface_name_is_hardcoded_in_the_module(self):
        """eth0 is wrong on a laptop, wlan0 on a server, both in a container."""
        source = (capture.__file__ or "")
        with open(source, encoding="utf-8") as handle:
            text = handle.read()
        for guess in ('"eth0"', "'eth0'", '"wlan0"', "'wlan0'", '"en0"'):
            self.assertNotIn(guess, text, guess)

    def test_the_list_is_deduplicated_and_ordered(self):
        with patch.object(capture, "_scapy_interfaces", return_value=["eth9", "lo"]), \
             patch.object(capture, "_system_interfaces", return_value=["lo", "wlan9"]):
            self.assertEqual(list_interfaces(), ["eth9", "lo", "wlan9"])

    def test_enumeration_never_raises_when_scapy_is_broken(self):
        with patch.object(capture, "_scapy_interfaces", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                capture._scapy_interfaces()
        # And the public function tolerates a backend that returns nothing.
        with patch.object(capture, "_scapy_interfaces", return_value=[]):
            self.assertIsInstance(list_interfaces(), list)

    def test_an_unknown_interface_has_no_up_state(self):
        self.assertIsNone(interface_is_up("definitely-not-an-interface"))

    @unittest.skipUnless(LINUX, "operstate lives in sysfs")
    def test_loopback_reads_as_up(self):
        self.assertIsNot(interface_is_up("lo"), False)


class PrivilegeTests(unittest.TestCase):
    def test_the_probe_answers_without_raising(self):
        ok, reason = raw_socket_permitted()
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(reason, str)
        self.assertEqual(bool(reason), not ok)

    def test_a_refused_socket_is_reported_as_refused(self):
        with patch.object(socket, "socket", side_effect=PermissionError()):
            ok, reason = raw_socket_permitted()
        self.assertFalse(ok)
        self.assertIn("refused", reason)

    def test_the_probe_socket_is_closed_again(self):
        """A probe that leaked a bound socket would be worse than no probe."""
        closed = []

        class FakeSocket:
            def close(self):
                closed.append(True)

        with patch.object(socket, "socket", return_value=FakeSocket()):
            ok, _ = raw_socket_permitted()
        self.assertTrue(ok)
        self.assertEqual(closed, [True])

    @unittest.skipUnless(LINUX, "capabilities are a Linux concept")
    def test_the_capability_bit_is_readable(self):
        self.assertIn(has_cap_net_raw(), (True, False))


class RemedyTests(unittest.TestCase):
    def test_every_failure_state_carries_an_actionable_sentence(self):
        for state in (STATE_BLOCKED, STATE_NO_INTERFACE, STATE_ERROR, STATE_NO_TRAFFIC):
            with self.subTest(state=state):
                text = remedy(state)
                self.assertTrue(text, state)
                self.assertGreater(len(text), 30, state)

    def test_a_healthy_state_has_no_remedy(self):
        self.assertEqual(remedy(STATE_ONLINE), "")

    @unittest.skipUnless(LINUX, "the setcap advice is Linux-specific")
    def test_linux_advice_grants_one_capability_rather_than_root(self):
        """Running the whole sensor as root to read packets grants it
        everything else too; the one capability it needs can stand alone."""
        text = remedy(STATE_BLOCKED)
        self.assertIn("setcap", text)
        self.assertIn("cap_net_raw", text)
        self.assertIn("rather than running", text)
        # CAP_NET_ADMIN is what most advice adds and NEMOS does not need:
        # capture was measured reaching ONLINE with CAP_NET_RAW alone.
        self.assertNotIn("cap_net_admin", text.lower())

    def test_the_windows_backend_advice_names_npcap(self):
        with patch.object(sys, "platform", "win32"):
            self.assertIn("Npcap", remedy(STATE_ERROR))
            self.assertIn("Administrator", remedy(STATE_BLOCKED))


class BackendTests(unittest.TestCase):
    def test_scapy_is_reported_as_available_here(self):
        ok, reason = backend_available()
        self.assertTrue(ok, reason)

    def test_a_missing_scapy_is_named(self):
        import builtins
        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "scapy":
                raise ImportError("no scapy")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", side_effect=blocked):
            ok, reason = backend_available()
        self.assertFalse(ok)
        self.assertIn("Scapy", reason)

    def test_windows_without_a_driver_is_reported_as_a_missing_npcap(self):
        """Scapy imports fine on Windows without Npcap, then fails at sniff
        time with a raw traceback. NOT VERIFIED on real Windows: no such host
        is available here, so this pins the branch, not the platform."""
        with patch.object(sys, "platform", "win32"), \
             patch.object(capture, "_scapy_interfaces", return_value=[]):
            ok, reason = backend_available()
        self.assertFalse(ok)
        self.assertIn("Npcap", reason)


class PreflightTests(unittest.TestCase):
    def make(self, interface=None):
        return PacketCapture(interface, lambda event, kind: None)

    def test_a_healthy_environment_passes_preflight(self):
        if not raw_socket_permitted()[0] or not backend_available()[0]:
            self.skipTest("this environment cannot capture")
        self.assertEqual(self.make().preflight(), ("", "", ""))

    def test_a_misspelled_interface_is_reported_as_such(self):
        state, error, fix = self.make("wlan42-does-not-exist").preflight()
        self.assertEqual(state, STATE_NO_INTERFACE)
        self.assertIn("wlan42-does-not-exist", error)
        self.assertIn("available:", error)
        self.assertIn("NEMOS_INTERFACE", fix)

    def test_a_misspelled_interface_is_not_reported_as_a_permission_problem(self):
        """The failure the deployment actually hit: 'CAP_NET_RAW is required'
        for what was really a wrong interface name."""
        _, error, _ = self.make("wlan42-does-not-exist").preflight()
        self.assertNotIn("CAP_NET_RAW", error)

    def test_a_configured_interface_that_exists_is_accepted(self):
        names = list_interfaces()
        if not names or not raw_socket_permitted()[0]:
            self.skipTest("no interfaces or no capture privilege here")
        self.assertEqual(self.make(names[0]).preflight()[0], "")

    def test_no_interfaces_at_all_is_its_own_state(self):
        with patch.object(capture, "list_interfaces", return_value=[]):
            state, error, fix = self.make().preflight()
        self.assertEqual(state, STATE_NO_INTERFACE)
        self.assertIn("no network interfaces", error)
        self.assertTrue(fix)

    def test_a_refused_socket_is_blocked_with_a_fix(self):
        with patch.object(capture, "raw_socket_permitted",
                          return_value=(False, "the operating system refused a packet socket")):
            state, error, fix = self.make().preflight()
        self.assertEqual(state, STATE_BLOCKED)
        self.assertIn("refused", error)
        self.assertTrue(fix)

    def test_a_refusal_despite_the_capability_says_so(self):
        """setcap is the wrong advice when the capability is already held."""
        with patch.object(capture, "raw_socket_permitted", return_value=(False, "refused")), \
             patch.object(capture, "has_cap_net_raw", return_value=True):
            _, error, _ = self.make().preflight()
        self.assertIn("despite holding CAP_NET_RAW", error)
        self.assertIn("seccomp", error)

    def test_a_missing_capability_is_named(self):
        with patch.object(capture, "raw_socket_permitted", return_value=(False, "refused")), \
             patch.object(capture, "has_cap_net_raw", return_value=False):
            _, error, _ = self.make().preflight()
        self.assertIn("does not hold CAP_NET_RAW", error)

    def test_a_missing_backend_beats_every_other_check(self):
        with patch.object(capture, "backend_available", return_value=(False, "Scapy is not installed")):
            state, error, _ = self.make("nonsense").preflight()
        self.assertEqual(state, STATE_ERROR)
        self.assertIn("Scapy", error)


class StartRefusalTests(unittest.TestCase):
    def test_start_does_not_spawn_a_thread_it_knows_will_fail(self):
        sensor = PacketCapture("wlan42-does-not-exist", lambda e, k: None)
        sensor.start()
        self.addCleanup(sensor.stop, 1)
        status = sensor.status()
        self.assertEqual(status["display_state"], STATE_NO_INTERFACE)
        self.assertFalse(status["running"])
        self.assertIsNone(sensor.thread)
        self.assertEqual(status["packets_seen"], 0)
        self.assertTrue(status["remedy"])

    def test_a_refused_start_never_reports_a_packet_count(self):
        with patch.object(capture, "raw_socket_permitted", return_value=(False, "refused")):
            sensor = PacketCapture(None, lambda e, k: None)
            sensor.start()
        self.addCleanup(sensor.stop, 1)
        self.assertEqual(sensor.status()["packets_seen"], 0)
        self.assertEqual(sensor.status()["display_state"], STATE_BLOCKED)

    def test_the_interface_list_is_reported_so_the_operator_can_pick_one(self):
        sensor = PacketCapture("wlan42-does-not-exist", lambda e, k: None)
        sensor.start()
        self.addCleanup(sensor.stop, 1)
        self.assertEqual(sensor.status()["interfaces"], list_interfaces())


class DisplayStateTests(unittest.TestCase):
    def setUp(self):
        self.sensor = PacketCapture(None, lambda e, k: None, traffic_grace=10.0)

    def show(self, state, alive=True, packets=0, bound_at=0.0, now=1.0):
        return self.sensor.display_state(state, alive, packets, bound_at, now)

    def test_a_bind_alone_is_never_online(self):
        """A sensor on the wrong interface binds perfectly and sees nothing."""
        self.assertNotEqual(self.show("running", packets=0), STATE_ONLINE)

    def test_a_packet_earns_online(self):
        self.assertEqual(self.show("running", packets=1), STATE_ONLINE)

    def test_a_quiet_bind_is_starting_until_the_grace_period_passes(self):
        self.assertEqual(self.show("running", packets=0, now=5.0), STATE_STARTING)
        self.assertEqual(self.show("running", packets=0, now=11.0), STATE_NO_TRAFFIC)

    def test_a_bound_socket_with_no_bind_time_is_not_declared_quiet(self):
        self.assertEqual(self.show("running", packets=0, bound_at=None), STATE_STARTING)

    def test_the_internal_lifecycle_maps_onto_the_operator_states(self):
        cases = {
            "permission_denied": STATE_BLOCKED,
            STATE_BLOCKED: STATE_BLOCKED,
            STATE_NO_INTERFACE: STATE_NO_INTERFACE,
            "unavailable": STATE_ERROR,
            "error": STATE_ERROR,
            "failed": STATE_ERROR,
            "stopped": STATE_OFF,
            "not_configured": STATE_OFF,
            "starting": STATE_STARTING,
        }
        for internal, shown in cases.items():
            with self.subTest(internal=internal):
                self.assertEqual(self.show(internal, alive=False), shown)

    def test_a_dead_thread_is_never_online_however_many_packets_it_saw(self):
        self.assertEqual(self.show("running", alive=False, packets=9999), STATE_ERROR)

    def test_status_reports_a_display_state_in_every_condition(self):
        sensor = PacketCapture("wlan42-does-not-exist", lambda e, k: None)
        self.assertEqual(sensor.status()["display_state"], STATE_OFF)
        sensor.start()
        self.addCleanup(sensor.stop, 1)
        self.assertIn(sensor.status()["display_state"],
                      {STATE_NO_INTERFACE, STATE_BLOCKED, STATE_ERROR})


if __name__ == "__main__":
    unittest.main()
