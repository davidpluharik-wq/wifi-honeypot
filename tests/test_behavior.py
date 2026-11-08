import queue
import threading
import unittest
from unittest.mock import patch, MagicMock
import honeypot_gui as honeypot


class BehaviorTests(unittest.TestCase):
    def test_honeypot_command_has_no_shell(self):
        with patch.object(honeypot.subprocess, 'run') as command:
            honeypot.run(['ip', 'link', 'show'], check=True)
        args, kwargs = command.call_args
        self.assertEqual(args[0], ['ip', 'link', 'show'])
        self.assertTrue(kwargs['check'])
        self.assertNotIn('shell', kwargs)

    def test_honeypot_cleanup_only_owned_resources(self):
        app = honeypot.HoneypotApp.__new__(honeypot.HoneypotApp)
        app.stop_flag = threading.Event()
        dns = MagicMock()
        ap = MagicMock()
        app.dnsmasq_proc, app.hostapd_proc = dns, ap
        app.address_added = True
        with patch.object(honeypot, 'run') as command:
            app._cleanup()
        dns.terminate.assert_called_once()
        ap.terminate.assert_called_once()
        command.assert_called_once_with(
            ['ip', 'addr', 'del', honeypot.AP_IP, 'dev', honeypot.INTERFACE], check=True)
        self.assertFalse(app.address_added)
        self.assertIsNone(app.hostapd_proc)

    def test_honeypot_startup_error_rolls_back(self):
        app = honeypot.HoneypotApp.__new__(honeypot.HoneypotApp)
        app.event_queue = queue.Queue()
        with patch.object(honeypot, 'run', side_effect=OSError('missing ip')), patch.object(app, '_cleanup') as cleanup:
            app._startup_sequence()
        cleanup.assert_called_once()
        self.assertEqual(app.event_queue.get_nowait(), ('status_error', 'missing ip'))
