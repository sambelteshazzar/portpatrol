import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "install.sh"


def run_install(home):
    env = dict(os.environ)
    env["HOME"] = str(home)
    return subprocess.run(
        ["bash", str(INSTALL_SH)],
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


def test_install_sh_end_to_end(tmp_path):
    first = run_install(tmp_path)
    assert first.returncode == 0, first.stdout + first.stderr

    venv = tmp_path / ".portpatrol" / "venv"
    assert (venv / "bin" / "portpatrol").is_file()

    link = tmp_path / ".local" / "bin" / "portpatrol"
    assert link.is_symlink()
    assert Path(os.path.realpath(link)) == venv / "bin" / "portpatrol"

    wrapper = tmp_path / ".portpatrol" / "bin" / "portpatrol-desktop.sh"
    assert wrapper.is_file()
    assert os.access(wrapper, os.X_OK)

    desktop = tmp_path / ".local" / "share" / "applications" / "portpatrol.desktop"
    assert desktop.is_file()
    exec_lines = [
        line for line in desktop.read_text(encoding="utf-8").splitlines()
        if line.startswith("Exec=")
    ]
    assert len(exec_lines) == 1
    exec_token = exec_lines[0][len("Exec="):].strip().strip('"')
    assert exec_token.startswith("/"), "installed Exec must be absolute"
    assert exec_token == str(wrapper)

    out = subprocess.run(
        [str(link), "explain", "22"],
        capture_output=True,
        text=True,
        timeout=60,
        env=dict(os.environ, HOME=str(tmp_path)),
    )
    assert out.returncode == 0, out.stdout + out.stderr
    assert "ssh" in out.stdout.lower()

    second = run_install(tmp_path)
    assert second.returncode == 0, second.stdout + second.stderr
