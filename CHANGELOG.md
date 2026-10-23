# Changelog

## 0.1.0 — 2026-10-22

First release.

- Finds Node.js installs: system/package, /opt, nvm, fnm, volta, asdf, n, nodenv, snap, VS Code / Cursor / code-server, plus `--search` folders
- Compares versions against the 21 Oct 2026 fixed releases (22.23.4 / 24.22.1 / 26.12.1)
- Flags end-of-life lines (20 and older, odd majors)
- Detects Debian/Ubuntu and RPM distro backports
- Checks every running Node process: actual binary and version, and processes on a replaced binary (restart needed)
- eMudhra CA check: NODE_EXTRA_CA_CERTS bundles with emSign/eMudhra certs, processes using the OS CA store
- Optional `--containers` check
- Reads versions without executing binaries where possible; runs other users' binaries as that user, never root
- Text and `--json` output, documented exit codes
