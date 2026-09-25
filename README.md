# PortPatrol

PortPatrol connects to TCP ports on 127.0.0.1 and reports which ones accept a connection. For each open port it names the service, rates the risk from a knowledge base you can edit, shows the owning process and whether the port listens on loopback or on your interfaces, and can list matching CVEs from the CISA Known Exploited Vulnerabilities catalog.

The scan side is plain Python 3.8+ with no third-party packages. A scan opens connections, reads banners, and closes them. PortPatrol sends no exploits and tries no credentials.

## Install

Python 3.8 or newer is the only hard requirement. Install `nmap` before the first scan if you can: the scan works without it, but ports the built-in probes do not recognize report `unknown` service and no version. Desktop toasts need `notify-send` on Linux; the [Optional tools](#optional-tools) table lists what each missing tool changes.

| Distro | Command |
| --- | --- |
| Debian, Ubuntu | `sudo apt install nmap libnotify-bin` |
| Fedora, RHEL | `sudo dnf install nmap libnotify` |
| Arch | `sudo pacman -S nmap libnotify` |
| openSUSE | `sudo zypper install nmap libnotify-tools` |
| Alpine | `sudo apk add nmap libnotify` |

On any other distro, both exist under their usual names: `nmap`, plus whichever package provides `notify-send` (commonly `libnotify`, `libnotify-bin`, or `libnotify-tools`).

On Windows, nmap installs from nmap.org and notifications use the built-in PowerShell toast, so no extra package is needed there.

### Linux

```
./install.sh
```

The installer checks for Python 3.8 or newer, builds a virtual environment at `~/.portpatrol/venv`, puts a `portpatrol` command in `~/.local/bin`, and installs the application-menu launcher. Run it again after pulling changes; a second run upgrades the same environment.

On Debian and Ubuntu `python3 -m venv` needs an extra package, and the installer prints the fix (`sudo apt install python3-venv`) when it is missing. The first pip run downloads a small build package, so an internet connection is needed once. If `~/.local/bin` is not on your PATH, the installer prints the line to add to your shell profile.

### Windows

```
powershell -ExecutionPolicy Bypass -File install.ps1
```

The PowerShell installer finds `py -3` or `python`, builds `%USERPROFILE%\.portpatrol\venv`, appends `%USERPROFILE%\.portpatrol\bin` to your user PATH, and puts a PortPatrol shortcut in the Start Menu. The PATH write reads and rewrites the registry value in place, so other PATH entries and their types survive, and a broadcast tells new terminals about it. The default execution policy blocks downloaded scripts, which is why the command above uses `Bypass`.

`install.ps1` and `portpatrol.bat` were written and reviewed on Linux; neither file has been executed on Windows.

### From a source checkout

```
python3 -m venv .venv
. .venv/bin/activate
pip install .
```

The last line puts a `portpatrol` command on your PATH. To run from the checkout without installing:

```
./bin/portpatrol scan
PYTHONPATH=. python3 -m portpatrol scan
```

## scan

```
$ portpatrol scan
  PORT  RISK     EXPOSURE  SERVICE          VERSION        PROCESS        CVES
  8000  🟡 medium  interface http-alt         -              MainThread     
   631  🔵 info    loopback  ipp              2.4            -              
```

Running `portpatrol` with no subcommand runs this same scan with the default options. Flags belong to `portpatrol scan`, which takes everything shown below.

Two ports are open on the machine that produced this output. Port 631 runs CUPS, listens on 127.0.0.1 only, and shows `info` because the knowledge base rates IPP as `medium` and the loopback binding drops every risk one level. Port 8000 listens on all interfaces and keeps its `medium` rating. `MainThread` is what the kernel reports as the process name for that listener.

Options:

- `--ports SPEC` picks the port set (see [Port sets](#port-sets)). Default `top1000`.
- `--json` prints the result document instead of the table. Notifications still fire unless you also pass `--no-notify`.
- `--kev` matches findings against the CISA KEV catalog and fills the `CVES` column. The feed is cached for 24 hours in `~/.portpatrol/kev.json`, so a run within a day of the last fetch needs no network access to cisa.gov.
- `--no-notify` keeps the run quiet on the desktop.
- `--verbose` writes progress and skipped enrichments to stderr: how many ports answered, when nmap is missing, when the listener table is unavailable.
- `--diff` compares against the previous scan (see [Change detection](#change-detection)).

A default scan here takes about 13 seconds, most of it inside nmap version detection. Without nmap the sweep and banner probes finish in about a second.

## explain

```
$ portpatrol explain 6379
Port 6379/tcp — redis — risk: critical
Advice: Unauthenticated Redis is a root-install path (cron and SSH key writes). Require auth, bind to localhost, and keep patched.
KEV hints: redis
```

Ports with no knowledge base entry print a note saying so and tell you to work out by hand what is listening. Either way the exit code is 0.

## watch

`portpatrol watch` re-scans on an interval and prints only when the picture changes:

```
$ portpatrol watch
🆕 PortPatrol changes — 1 new: 9001 (unknown)
```

That line appeared after a process started listening on 9001 during a watch run. The first cycle has nothing to compare against, so it stores the current open ports as the baseline and stays silent (a summary toast goes out unless you passed `--no-notify`). Cycles with nothing new print nothing; add `--verbose` for a status line on stderr:

```
portpatrol: 2 open of 3 scanned
portpatrol: cycle 3 open=2 changes=0
```

`--interval` sets the delay in seconds, default 60, minimum 1. Ctrl+C exits with code 0. Bad arguments or a failed cycle exit 2. The other options match `scan`: `--ports`, `--kev`, `--no-notify`, `--verbose`. There is no `--json` in watch mode.

## Change detection

`scan --diff` and `watch` share one baseline: `~/.portpatrol/state.json`, which holds the port, service, version, and risk of every open port from the last run. The next run reports three kinds of change: ports that appeared, ports that disappeared, and ports whose service or version moved. A run with no saved state establishes the baseline instead.

The console table prints in full on every `scan --diff` run. Change alerts go out as notifications: a summary toast for the baseline, a change toast afterward, plus a separate toast for each newly opened critical port. Scripts that want the change data should use `--json`, which adds `changes` and `baseline` keys to the result document.

`~/.portpatrol/allowlist.json` holds ports you expect and do not want alerts for. It is a plain JSON array of port numbers:

```json
[8000, 9001]
```

Allowlisted ports never show up under `new`. They still appear in the console table, and a change to an existing port's service or version still counts as a change.

`watch` appends to history only on cycles where something changed, so cycles with nothing new add no records. Every `scan` run appends, diff or not.

## Port sets

`--ports` accepts:

| Spec | Ports |
| --- | --- |
| `top50` | the first 50 entries of `data/top_ports.json` |
| `top100` | the first 100 entries of that list |
| `top1000` | 1-1023 plus the top 100 (default) |
| `all` | 1-65535 |
| `80,443` | any comma-separated list |
| `8000-8100` | any range, mixable with lists in one spec |

Anything else, including a number above 65535, fails with exit code 2 and a message on stderr:

```
$ portpatrol scan --ports 99999
portpatrol: invalid port: '99999'
```

## Exit codes

| Code | scan | watch | explain |
| --- | --- | --- | --- |
| 0 | no open ports | interrupted with Ctrl+C | always |
| 1 | at least one open port | | |
| 2 | bad arguments or port spec | bad `--interval`, bad port spec, or a failed cycle | |

A bare `portpatrol` uses the `scan` column.

## JSON output

```
$ portpatrol scan --ports 631 --json
{
  "timestamp": "2026-09-25T08:23:44Z",
  "target": "127.0.0.1",
  "scanned": 1,
  "open": [
    {
      "port": 631,
      "service": "ipp",
      "version": "2.4",
      "product": "CUPS",
      "pid": null,
      "process": null,
      "exposure": "loopback",
      "risk": "info",
      "cves": []
    }
  ]
}
```

`pid` and `process` come from the OS listener table. They read `null` when the owning process belongs to another user and the kernel hides it from you. With `--diff` the document also carries `changes` (`new`, `removed`, `changed`) and `baseline`.

## Risk ratings

Each entry in the knowledge base assigns one of five ratings: `critical`, `high`, `medium`, `info`, `unknown`.

The lookup runs in a fixed order. A knowledge base entry for the open port wins. With no entry, the service name picked up from the banner or from nmap is looked up among the other entries, and a match brings in that entry's rating. A port with neither reads as `unknown`.

Exposure adjusts the result once. A listener bound to 127.0.0.1 or ::1 drops one level: critical to high, high to medium, medium to info. Listeners on other interfaces, and cases where the listener table is unavailable, keep the rating unchanged.

Identification runs in three passes. The knowledge base entry for the port sends its probe (`PING\r\n` for Redis, a `HEAD` request for HTTP ports) or reads the greeting for banner-first services such as SSH and FTP. An unmatched banner is then matched against every entry in the knowledge base. Whatever remains unknown goes to `nmap -sV --version-light` when nmap is installed, which supplies the service name, product, and version you see in the table.

## Knowledge base

The file loads in this order, and the first one that parses wins:

1. `~/.portpatrol/knowledge_base.json`
2. the packaged `portpatrol/knowledge_base.json`
3. the built-in defaults in `portpatrol/defaults.py`, with a warning on stderr

Your file replaces the packaged one. It does not merge, so copy across the entries you want to keep before you start editing. The packaged file and the built-in defaults are identical lists of 45 ports.

An entry looks like this:

```json
{
  "port": 6379,
  "protocol": "tcp",
  "service": "redis",
  "risk": "critical",
  "banner_first": false,
  "probe": "PING\r\n",
  "match": ["^\\+PONG", "^-ERR", "^\\$\\d"],
  "advice": "Unauthenticated Redis is a root-install path (cron and SSH key writes). Require auth, bind to localhost, and keep patched.",
  "kev_hints": ["redis"]
}
```

`probe` is the string sent to the port; leave it `null` for services that greet first and set `banner_first` instead. `match` is a list of regular expressions run against the response; the first capturing group of the first matching pattern becomes the reported version. `kev_hints` are lowercase keywords searched against the KEV catalog's vendor, product, and description fields when you pass `--kev`. `advice` is what `portpatrol explain` prints.

## Files in ~/.portpatrol

| File | Written by | Contents |
| --- | --- | --- |
| `history.json` | every scan, changing watch cycles | array of full result documents, oldest first |
| `state.json` | `scan --diff`, `watch` | slim baseline: port, service, version, risk |
| `allowlist.json` | you | array of port numbers exempt from "new port" alerts |
| `kev.json` | `--kev` | cached CISA KEV feed, refreshed after 24 hours |
| `knowledge_base.json` | you | optional replacement knowledge base |

PortPatrol creates the directory on first write and keeps every file it saves there.

## Optional tools

| Tool | Used for | When it is missing |
| --- | --- | --- |
| `nmap` | service, product, and version on ports the probes could not name | socket probes alone; the table shows `unknown` service or no version |
| `notify-send` | desktop toasts on Linux | console output only, exit codes unchanged |
| `ss` (Linux), `netstat` (Windows) | process name, PID, bind address, exposure class | `PROCESS` reads `-`, exposure reads `unknown`, no loopback downgrade |

Windows notifications use a PowerShell toast and fall back to a message box if the toast API is unavailable. Both paths share one code base. Only the Linux one has been exercised.

## Double-click launcher

`portpatrol-desktop.sh` opens a terminal, runs a scan, and waits for Enter so the result stays on screen. `install.sh` places it as the `portpatrol` entry in your application menu. Without the installer, copy the desktop file and point its `Exec` line at wherever the wrapper sits:

```
mkdir -p ~/.local/share/applications
cp examples/desktop/portpatrol.desktop ~/.local/share/applications/
```

The shipped `Exec=portpatrol-desktop.sh` resolves through `PATH`; change it to the wrapper's full path if the wrapper is not on `PATH`.

On Windows, the installer's Start Menu shortcut runs `portpatrol-desktop.bat`, which scans and then waits for a key press. From a source checkout the same job falls to `portpatrol.bat` in the repository root: it prefers the installed venv command and otherwise runs `py -3 -m portpatrol`, then pauses.

## Scheduled scans

Example systemd user units live in `examples/systemd/user/`. They run a daily `scan --ports top1000 --kev --diff` at 09:00 and treat exit code 1 as success:

```
mkdir -p ~/.config/systemd/user
cp examples/systemd/user/portpatrol-daily.* ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now portpatrol-daily.timer
```

The service file calls `%h/portpatrol/bin/portpatrol`, so edit `ExecStart` if your checkout sits somewhere else.

## Tests

```
python3 -m pytest
```

from the repository root. 122 tests cover the sweep, banner and probe matching, nmap and KEV enrichment with mocked subprocesses, the listener parsers, the diff engine, notifications, rendering, the CLI including watch cycles, and the installers. The suite runs against real listeners bound to ephemeral ports, and `install.sh` is exercised end to end against a scratch home directory.
