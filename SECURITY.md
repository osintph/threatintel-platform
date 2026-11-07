# Security policy

## Supported versions

Security fixes go into the newest release only. Upgrade an install with
`sudo ./upgrade.sh` (see [docs/runbook.md](docs/runbook.md)); the release notes say
what to read before you do.

## Reporting a vulnerability

Please do not open a public issue or pull request for a security problem.

Report it privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**, or go straight to
<https://github.com/osintph/threatintel-platform/security/advisories/new>.
The report is visible only to you and the maintainers, and the answer comes in the
same thread.

It helps to include:

- the version (`docker compose exec dashboard python -c "from darkweb_scanner import __version__; print(__version__)"`) or the commit;
- what you did, what happened, and what you expected;
- the smallest example that shows the problem.

Please test only against an install of your own, and leave out other people's data
and working exploit chains: enough to reproduce the problem is enough.

## Scope

The code in this repository and the container images built from it: the dashboard,
the crawler, the nginx and Tor containers, `deploy.sh`, `upgrade.sh` and the scripts
under `ops/` and `scripts/`.

Outside it: the third-party services the dashboard can query, and the configuration
of a particular server (firewall, DNS, CDN).

## Licence of fixes

All patches submitted in response to security issues
must comply with the GNU Affero General Public License v3.0 (AGPL-3.0-only).
