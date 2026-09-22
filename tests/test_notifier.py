from unittest import mock

from portpatrol import notifier


def test_summary_message_clear():
    assert notifier.summary_message([]).startswith("✅ PortPatrol: all clear")


def test_summary_message_counts_and_emoji():
    findings = [
        {"port": 22, "risk": "info"},
        {"port": 445, "risk": "high"},
        {"port": 23, "risk": "critical"},
    ]
    msg = notifier.summary_message(findings)
    assert msg.startswith("🚨 PortPatrol: 3 open ports")
    assert "1 critical" in msg
    assert "1 high" in msg
    assert "1 info" in msg


def test_summary_message_unknown_only():
    msg = notifier.summary_message([{"port": 40000, "risk": "unknown"}])
    assert msg.startswith("❓ PortPatrol: 1 open ports")


def test_notify_linux_uses_notify_send():
    with mock.patch("portpatrol.notifier.shutil.which", return_value="/usr/bin/notify-send"), \
         mock.patch("portpatrol.notifier.subprocess.run") as run:
        assert notifier.notify("t", "b") is True
    assert run.call_args[0][0][0] == "notify-send"


def test_notify_linux_fallback_when_missing():
    with mock.patch("portpatrol.notifier.shutil.which", return_value=None):
        assert notifier.notify("t", "b") is False


def test_windows_powershell_script_contains_text():
    script = notifier._windows_powershell_script("title", "body")
    assert "ToastNotificationManager" in script
    assert "'title'" in script
    assert "'body'" in script
