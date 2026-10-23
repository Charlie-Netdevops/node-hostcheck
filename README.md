# node-hostcheck

A free, **read-only** host check for the **Node.js October 2026 security release**: the Brotli decoder RCE (CVE-2026-111497), three TLS certificate hostname bypasses, and 6 more. Fixed in **22.23.4 / 24.22.1 / 26.12.1**.

`node --version` only tells you about the Node in *your* shell. A real server often has several: the system package, nvm / fnm / volta / asdf / n / nodenv versions in user homes, snap, the copy bundled with VS Code Server, an app-bundled runtime, and whatever PM2 or systemd actually starts. Node apps are long-running, so after patching, the old vulnerable code keeps running until each process is restarted.

This script finds them all, checks every **install** *and* every **running process**, and tells you exactly what still needs updating or restarting.

> Indicator check only. A clean result is not proof that a host is safe. Only run it on systems you own or are authorised to check.

## What it checks

| Check | Why it matters |
|---|---|
| **Every Node install**: system/package, `/opt`, nvm, fnm, volta, asdf, n, nodenv, snap, VS Code / Cursor / code-server, plus any folder you pass with `--search` | Your shell's `node` is rarely the only one |
| **Version vs. fixed releases** (22.23.4 / 24.22.1 / 26.12.1) | Tells you what's unpatched |
| **End-of-life lines** (20 and older, plus odd majors 21/23/25) | They get no fix at all |
| **Distro backports** (Debian/Ubuntu and RPM changelogs) | Avoids false alarms on patched distro packages |
| **Every running Node process**: which binary and version it's *actually* using | A service can run an old nvm version even after you installed the new one |
| **Processes on a replaced binary** | Updated on disk but not restarted, so the old code is still live |
| **eMudhra CA distrust**: `NODE_EXTRA_CA_CERTS` bundles containing emSign/eMudhra certs, and processes using the OS CA store | Updating Node doesn't remove certificates you add yourself |
| **Docker containers** (`--containers`, optional) | Updating the host doesn't update images |

## Safe by design

- **No network traffic, no exploit probes, changes nothing.**
- **It avoids executing binaries it finds.** It reads the version from Node's own `node_version.h`, package metadata, or the install path first. If it really has to run `node --version` on a binary owned by another user, it runs it **as that user, not root**, so a planted file in someone's home folder can't run with root rights.
- `--containers` runs only `node --version` inside running containers.

## Quick start

Download it, **read it**, then run it:

```bash
curl -fsSLO https://raw.githubusercontent.com/Charlie-Netdevops/node-hostcheck/main/node-hostcheck.sh
less node-hostcheck.sh
chmod +x node-hostcheck.sh
sudo ./node-hostcheck.sh
```

Include app folders and containers:

```bash
sudo ./node-hostcheck.sh --search /srv --search /opt/apps --containers
```

Requirements: Linux, bash 4+, standard tools. `openssl` is optional, for the CA bundle check. Run as root for full results.

## Options

```
--json            Machine-readable JSON output (for n8n, cron, SIEM)
--containers      Also run 'node --version' inside running Docker containers
--search DIR      Extra directory to search for node binaries (repeatable)
--no-color        Disable colours
-V, --version     Show version
-h, --help        Show help
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Every Node install and running process found is patched |
| `1` | **Vulnerable**: unpatched/EOL Node installed or running, or a restart is needed |
| `2` | **Needs attention**: unknown versions, EOL with a backport, or CA bundle issues |
| `3` | No Node.js found |
| `64` | Bad arguments |

## Example output

```
node-hostcheck 0.1.0 — Node.js October 2026 security release (CVE-2026-111497 + 9)

NODE.JS INSTALLS
  [VULNERABLE] 22.22.0  path   /opt/node22/bin/node
  [EOL] 20.20.0         system /opt/node20/bin/node
  [PATCHED] 24.22.1     nvm    /home/app/.nvm/versions/node/v24.22.1/bin/node

RUNNING NODE.JS PROCESSES
  [VULNERABLE] PID 478  app  22.22.0  /opt/node22/bin/node
  [RESTART_NEEDED] PID 488  app  ?  /usr/bin/node

FINDINGS
  [HIGH] Running Node.js processes on a replaced binary — restart needed
  [HIGH] Running Node.js processes using a vulnerable or end-of-life version
  [MEDIUM] Extra CA bundles for Node.js contain eMudhra / emSign certificates

RESULT: VULNERABLE — update Node.js and restart the processes listed above.
```

Note the nvm 24.22.1 install is patched, but the app is still running the old 22.22.0. That's exactly the case `node --version` won't show you.

## If it says VULNERABLE

1. **Update** to 22.23.4 / 24.22.1 / 26.12.1, or your distro's fixed package.
2. **nvm/fnm/volta:** install the fixed version, point your services at it (PM2 ecosystem file, systemd `ExecStart`), and remove the old version.
3. **Restart** every Node process (`pm2 restart all`, `systemctl restart <app>`), then run the check again.
4. **Rebuild** Docker images (`docker build --pull`) and single-executable apps, since they carry their own Node.
5. **Node 20 and older** are end-of-life: move to Node 24 or 26.

## Limitations

- Fixed-version data is as of `DATA_DATE` (2026-10-22). Update the `FIXED` table if Node ships a follow-up.
- It won't find Node embedded inside other programs (Electron apps, some vendor tools) unless you point `--search` at them, and even then only files named `node`.
- Single-executable apps (SEA) and startup snapshots aren't detected. Rebuild them after updating.
- Backport detection needs distro changelogs, which minimal images often strip.
- Without root, other users' installs and processes can't be fully checked.

## Related

- [php2shell-hostcheck](https://github.com/Charlie-Netdevops/php2shell-hostcheck): the same approach for the PHP2Shell RCE.

## References

- Node.js security release, 21 Oct 2026: <https://nodejs.org/en/blog/vulnerability/october-2026-security-releases>

## Disclaimer

Provided as-is, without warranty of any kind. You are responsible for how and where you run it. See [LICENSE](LICENSE).
