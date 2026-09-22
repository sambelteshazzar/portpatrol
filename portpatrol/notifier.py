"""Cross-platform desktop notifications with emoji risk indicators."""

from __future__ import annotations

import shutil
import subprocess
import sys

EMOJI = {
    "critical": "🚨",
    "high": "⚠️",
    "medium": "🟡",
    "info": "🔵",
    "unknown": "❓",
    "clear": "✅",
}

RISK_ORDER = ["critical", "high", "medium", "info", "unknown"]


def summary_message(findings):
    """Build the summary toast text, e.g. "🚨 PortPatrol: 3 open ports — 1 critical, 1 high, 1 info"."""
    if not findings:
        return "✅ PortPatrol: all clear — no open ports found"
    counts = {}
    for f in findings:
        counts[f["risk"]] = counts.get(f["risk"], 0) + 1
    top = next(r for r in RISK_ORDER if r in counts)
    parts = [f"{counts[r]} {r}" for r in RISK_ORDER if r in counts]
    return f"{EMOJI[top]} PortPatrol: {len(findings)} open ports — {', '.join(parts)}"


def _linux_command(title, body):
    return ["notify-send", title, body]


def _windows_powershell_script(title, body):
    esc_title = title.replace("'", "''")
    esc_body = body.replace("'", "''")
    return (
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
        "ContentType = WindowsRuntime] | Out-Null; "
        "$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
        "[Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
        f"$t.GetElementsByTagName('text').Item(0).AppendChild($t.CreateTextNode('{esc_title}')) | Out-Null; "
        f"$t.GetElementsByTagName('text').Item(1).AppendChild($t.CreateTextNode('{esc_body}')) | Out-Null; "
        "$toast = [Windows.UI.Notifications.ToastNotification]::new($t); "
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('PortPatrol').Show($toast)"
    )


def notify(title, body):
    """Send a desktop notification. Returns True when a channel delivered it."""
    if sys.platform == "win32":
        return _notify_windows(title, body)
    return _notify_linux(title, body)


def _notify_linux(title, body):
    if shutil.which("notify-send") is None:
        return False
    try:
        subprocess.run(_linux_command(title, body), timeout=10, check=False)
        return True
    except OSError:
        return False


def _notify_windows(title, body):
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             _windows_powershell_script(title, body)],
            capture_output=True, timeout=15, check=False,
        )
        if proc.returncode == 0:
            return True
    except OSError:
        pass
    return _notify_windows_fallback(title, body)


def _notify_windows_fallback(title, body):
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, body, title, 0x40)
        return True
    except (OSError, AttributeError, ImportError):
        return False
