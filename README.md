# BountyHub

A self-hosted Flask application for running reconnaissance against a target and
turning what comes back into tracked, reportable bug bounty findings.

BountyHub is the web front end of a three-part toolchain:

| Repository | Role |
|---|---|
| **BountyHub** (this repo) | Web UI, findings database, scan orchestration, PDF reports |
| [scan-engine](https://github.com/malek-sec/scan-engine) | The scanning pipeline — recon, fingerprinting, active fuzzing, AI advisor |
| [JS-Oracle](https://github.com/malek-sec/JS-Oracle) | JavaScript analysis — endpoints, secrets, auth logic |

BountyHub imports `scan-engine` directly as a Python package, so the two are
normally cloned side by side. Without it, the app still runs as a findings
tracker; the scan tab reports the engine as unavailable instead of failing.

> Use this only against systems you have explicit written authorisation to test.
> Running recon or fuzzing against a target outside an authorised program scope
> is illegal in most jurisdictions and violates the terms of every bounty platform.

---

## What it does

**Scanning.** Start a scan from the dashboard against a bare domain. A background
worker drives the scan-engine pipeline stage by stage and streams progress to the
browser:

1. `recon` — passive subdomain enumeration, live host probing, screenshots
2. `fingerprint` — port scanning and technology stack detection
3. `active_recon` — optional deep phase: katana crawl, ffuf, arjun, naabu, nuclei
4. `js_oracle` — JavaScript analysis of the files discovered during recon
5. `report` — findings written up, either offline or via a Claude synthesis

Scans are cancellable mid-flight, poll their own status over a JSON API, and are
reconciled on boot — a job left `running` by a killed process is marked failed
rather than resurrected as a scan you cannot stop.

**Cost control.** Every scan runs in one of two modes. `free` is the default and
costs nothing: JS analysis and the final report are produced by the deterministic
offline path with no model call. `ai` spends API credit for per-file Claude
analysis and a synthesised report. A saved free scan can be upgraded to an AI
report later from the scan history, reusing the findings already on disk instead
of re-scanning.

**Findings management.** Submit vulnerabilities with severity, CVSS score,
reproduction steps, impact, remediation, tags, and a proof-of-concept image.
Group them under programs, track status through to payout, and browse an archive
and a timeline view.

**Payouts.** Record bounty amounts and currency per finding, track paid/unpaid
state, and read back an earnings summary.

**CVE lookup.** Versioned technologies from a fingerprint are checked against the
NVD API, rate-limited to stay inside NVD's published budget and cached locally so
repeated lookups are free.

**Reports.** Export a finding or a whole scan to PDF via WeasyPrint, rendered
server side from the stored Markdown.

**Notifications.** Optional Telegram, Slack, and Discord webhooks fire on scan
completion and failure.

**Feature flags.** Ship work in progress behind a flag with percentage rollout,
toggled from the admin page.

---

## Requirements

- Python 3.10 or newer
- [scan-engine](https://github.com/malek-sec/scan-engine) cloned as a sibling
  directory, plus its external tools, if you want scanning
- A system with the WeasyPrint native dependencies available, for PDF export

## Install

```bash
git clone https://github.com/malek-sec/BountyHub.git
git clone https://github.com/malek-sec/scan-engine.git   # sibling, for scanning

cd BountyHub
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configure

```bash
cp .env.example .env
```

Fill in `.env`:

```ini
# Required. The app refuses to boot without a key of at least 32 characters.
# Generate one with: python3 -c "import secrets; print(secrets.token_hex(32))"
FLASK_SECRET_KEY=

# Required only for AI-mode scans and AI report generation.
ANTHROPIC_API_KEY=

# Optional alerting. Leave blank to disable.
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# Never set to 1 outside local development.
FLASK_DEBUG=0

# Optional. If unset, a random admin password is printed once on first boot.
ADMIN_INIT_PASSWORD=
```

Additional environment variables:

| Variable | Default | Effect |
|---|---|---|
| `BOUNTYHUB_DEFAULT_AI_MODE` | `free` | Default cost mode for new scans (`free` or `ai`) |
| `SLACK_WEBHOOK_URL` | unset | Slack notifications |
| `DISCORD_WEBHOOK_URL` | unset | Discord notifications |

The scan-engine tunables (rate limits, tool budgets, the active-recon kill
switch) are read from the engine's own environment variables. See the
[scan-engine README](https://github.com/malek-sec/scan-engine#configuration).

## Run

```bash
python3 app.py
```

The app binds to `127.0.0.1:5000` and does not listen on external interfaces.
On first boot it creates the SQLite database, seeds the default feature flags,
and creates the `admin` user. If you did not set `ADMIN_INIT_PASSWORD`, the
generated password is printed to stdout once — save it before you close the
terminal.

Schema migrations are managed with Alembic:

```bash
flask db upgrade
```

Existing SQLite databases created by `create_all()` also receive an idempotent
column top-up on every boot, so an older database is upgraded in place without a
manual migration step.

---

## Security model

BountyHub handles unreleased vulnerability details about third-party systems.
It is built to be run locally by one operator, and the defaults reflect that:

- **No default secret key.** `Config.validate()` raises at startup if
  `FLASK_SECRET_KEY` is missing or shorter than 32 characters. There is no
  insecure fallback to forget to override.
- **Debug off, loopback only.** `FLASK_DEBUG` defaults to `0` and the server
  binds `127.0.0.1`. The Werkzeug debugger is never exposed by accident.
- **Authentication everywhere.** Every route outside `/login` requires an
  authenticated session. There are no `@csrf.exempt` endpoints — CSRF protection
  is global and unconditional.
- **API routes return 401 JSON**, not an HTML login redirect, so an expired
  session surfaces cleanly to the polling front end instead of corrupting it.
- **Object-level authorisation.** Every query that reaches a finding, program,
  scan, or payout is scoped by `user_id`, so an object ID from another account
  returns nothing.
- **Rate limiting.** Global limits via Flask-Limiter, with a tighter
  5-per-minute cap on scan creation.
- **Passwords** are hashed with PBKDF2-SHA256. The bootstrap admin password is
  generated with `secrets.token_urlsafe` and shown once.
- **Uploads** are validated by magic bytes, not by the filename extension the
  client claims. Only JPEG, PNG, GIF, and WEBP are accepted, capped at 5 MB, and
  stored under a `secure_filename` timestamped name.
- **Markdown is sanitised client side** with DOMPurify, served from a local copy
  so a CDN outage can never silently degrade into an unsanitised fallback.
- **PDF report bodies are sanitised server side** with a `bleach` allow-list
  before they reach the template that renders them. This is not only an XSS
  control: WeasyPrint resolves URLs while laying out the page, so restricting
  protocols to `http`, `https`, and `mailto` is what stops a `file://` reference
  in a report body from pulling local file content into the PDF. Disallowed
  markup is escaped rather than dropped, so a quoted XSS payload stays readable
  as evidence instead of being silently gutted. If `bleach` is missing the PDF
  is not produced at all — the path fails closed.
- **Target input is strictly validated.** Only well-formed bare hostnames reach
  the scan engine; URLs, IP addresses, and shell metacharacters are rejected at
  the API boundary. No subprocess in the toolchain uses a shell.

Everything sensitive lives in `.env` and the SQLite database, both git-ignored.
Scan output, uploads, screenshots, and generated PDFs are ignored as well.

---

## Layout

```
app.py                 Application factory, bootstrap, schema top-up
config.py              Configuration and startup validation
extensions.py          SQLAlchemy, Login, Limiter, CSRF singletons
models/                User, Vulnerability, Program, ScanJob, CVECache,
                       FeatureFlag, ActivityLog
routes/                auth, vulnerabilities, scans, programs, payouts, admin
services/              scan, cve, cvss, payout, pdf, notify, upload
templates/             Jinja2 views
static/                Theme, local DOMPurify and marked, uploads, screenshots
migrations/            Alembic revisions
tests/                 Unit tests
```

## Tests

```bash
python3 -m pytest tests/
```

## License

MIT - see [LICENSE](LICENSE).
