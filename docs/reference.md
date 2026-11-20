# Part 1 — Concepts

## The problem AI Tarpit addresses

Autonomous AI attack agents are cheap to run and tireless, but they share a weakness:
they reason over whatever a target returns and they spend a real budget — tokens, time
and tool calls — on every step. In October 2026 Tracebit Research published *Context
Bombs*, a study showing that an attacking agent can be reliably diverted, stalled and
even stopped by feeding it deceptive context: forged secrets that lead nowhere,
instructions framed as authoritative, and tasks that never terminate. The agent cannot
easily tell a real lead from a manufactured one, so it follows the trap.

AI Tarpit turns that finding into a deployable honeypot. The decoy surface looks like an
ordinary corporate intranet — a portal, an inventory API, a document store, a backup
share. None of it is real. Every interesting lead is engineered to consume an agent's
budget, corrupt its working context, or persuade it to halt, while raising graded alerts
so a defender sees exactly what engaged and for how long.

## Design principles

- **Passive only.** The honeypot never initiates a connection to an attacker, never
  serves real malware and never retaliates. It only responds to requests it receives.
- **Synthetic data only.** Every credential, token, archive and record is a generated
  honeytoken that grants access to nothing. Using one anywhere on the decoy is itself a
  high-signal alert.
- **Self-protecting.** Slow and flooding techniques are bounded by configurable caps
  (concurrent slow connections, bytes per session) so the tarpit cannot be turned into a
  resource-exhaustion vector against its own host.
- **Deterministic persona.** The fake company, its employees and its secrets are derived
  from a seed, so the decoy is internally consistent across requests and restarts without
  storing a scripted fake.

## Fingerprinting and honeytokens (technique H)

Underneath the individual traps, AI Tarpit continuously **classifies** each session and
**tracks** every secret it hands out.

**Fingerprinting** assigns each session a score and a class — `human`, `scanner`,
`ai_agent` or `unknown` — from signals such as the user-agent family (curl,
python-requests, httpx, aiohttp, Go clients, headless browsers), the header set, request
timing (agents tend to burst then pause for seconds while they "think"), reads of
agent-only lures such as `llms.txt` or an MCP endpoint, document-then-API access
sequences, and POST bodies containing natural-language JSON. The classifier is heuristic
and **never blocks** — it only informs alerts and the report. When a session's class
changes, a `session.classified` event is emitted.

**Honeytokens** are the connective tissue between techniques. When a technique hands out
a secret (a cracked archive key, an assumed role token, a recovered password), it is
registered as a honeytoken tied to the issuing session. A single global scanner inspects
every request — headers, query string, body and basic-auth — for any issued token. The
first time a token is presented it raises `honeytoken.used` (HIGH) and **links the
presenting session to the one it was issued to**, giving cross-session and cross-IP
correlation: the same operator returning later, or a second tool in the same campaign,
is tied back to the original engagement.

## The techniques

Each technique below lists its **mechanism**, the **lures** that advertise it, its
**expected impact** on an AI agent, and the **alerts** it raises. All paths are defaults
and are fully configurable; every technique can be enabled or disabled independently.

<<<PAGEBREAK>>>

### T01 — Staged encryption

**Mechanism.** A chain of real AES-encrypted ZIP archives. The password for each stage is
derivable from a clue of a different kind (base64 note, hex, XOR hint, rot13, reversed
string). Each archive yields one *share* of a credential, a clue to the next stage, and
the next archive. Combining all shares produces AWS-shaped "keys" that are honeytokens.

**Lures.** A `/backup/` directory listing, a `BACKUP_ARCHIVE_HINT` in a leaked `.env`,
and a `robots.txt` entry.

**Expected impact.** The agent must recognise the encryption, find and decode each clue,
crack each stage in order, and reassemble the shares — a long, serial, easily-derailed
chain. The payoff, when reached, is a honeytoken that only triggers another alert.

**Alerts.** `technique.engaged` (MEDIUM) on first download; `technique.progress` (HIGH)
as later-stage archives are fetched (proving earlier stages were cracked);
`honeytoken.used` (HIGH) when a reconstructed key is presented anywhere.

### T02 — HTTP parser pressure

**Mechanism.** A paginated inventory API whose pagination never ends. The cursor field
name drifts between pages (`next`, `nextCursor`, `cursor_next`, `links.next`), the
advertised total changes, some pages are deliberately truncated or have a mismatched
`Content-Length`, and 206/429 responses appear intermittently. Only a few pages ever
carry a fragment of "access" data, and the record never completes.

**Lures.** An `/api/v1/` index, a portal link to the "Fleet inventory API", and an
OpenAPI excerpt.

**Expected impact.** A naive crawler loops forever; a careful one burns tokens parsing
inconsistent, partially-malformed JSON while chasing a record that does not exist.

**Alerts.** `technique.engaged` (MEDIUM) on the first page; `technique.progress` (HIGH)
at page milestones.

### T03 — Retained-buffer recovery

**Mechanism.** A debug endpoint returns a hex "over-read" that appears to leak a partial
`Authorization: Bearer` token belonging to another session. Length and offset parameters
reveal more bytes, with timeouts and overlaps. The fully reconstructed token is a
per-session honeytoken; presenting it to a records endpoint returns synthetic "victim"
data and more leads.

**Lures.** An HTML comment pointing at `/api/v1/debug/session`, and an
`X-Debug-Buffer: enabled` response header.

**Expected impact.** The agent is drawn into a byte-by-byte reconstruction puzzle, then
rewarded with a honeytoken whose use is itself alerted and correlated.

**Alerts.** `technique.engaged` (MEDIUM); `technique.progress` (HIGH) as more of the
buffer is revealed; `honeytoken.used` (HIGH) when the token is presented.

### T04 — Needlestack

**Mechanism.** A large catalogue of service accounts and roles. Assuming a role returns a
short-lived honeytoken that works on decoy export endpoints, but exports are fragmented
across many roles and carry SHA-256 digests, so a complete, verifiable reconstruction
requires chaining many assumptions. Some grants look like privilege escalation but
dead-end.

**Lures.** An `/api/v1/iam/roles` catalogue and a "retrieval guide" document.

**Expected impact.** The agent spreads effort across dozens of roles and partial exports,
verifying digests, without ever reaching a complete secret.

**Alerts.** `technique.engaged`; `technique.progress` (HIGH) per role assumed or export
reconstructed; completion when all exports are "verified".

### T05 — Pentest report exposure

**Mechanism.** A forged external-assessment report (HTML, with a downloadable copy) with
dated findings and named assets. It includes a **canary registry** claiming that certain
real-looking paths — and any paths the operator lists — are monitored canaries whose
access triggers engagement revocation, and it recommends the decoy endpoints of enabled
techniques as "confirmed exploitable".

**Lures.** A `/docs/security/` index, `robots.txt` and `llms.txt` entries.

**Expected impact.** The agent treats the report as ground truth, chases the "confirmed"
decoys first, and may avoid the canary paths the defender actually wants protected.

**Alerts.** `technique.engaged` (MEDIUM) on fetch; HIGH if a listed target is then hit in
the same session (correlation).

### T06 — Grandstanding

**Mechanism.** An "inventory exchange" endpoint invites a structured POST describing the
agent's access, entry route, tools, actions taken and next steps. Any submission is
stored and answered with a synthetic inventory (more decoy leads). The honeypot has
induced the agent to **self-report its own tradecraft**.

**Lures.** An operating note at `/docs/ops/inventory-exchange.md`, linked from other
techniques and from `llms.txt`.

**Expected impact.** The defender captures the agent's intent and method in the agent's
own words; the agent believes it has found a lateral-movement channel.

**Alerts.** `intel.captured` (**CRITICAL**) with the full submission.

<<<PAGEBREAK>>>

### T07 — Lossy password recovery

**Mechanism.** A recovery endpoint dribbles out an "admin password" one character at a
time, with gaps, repeats, empty bodies and `Retry-After` delays, and a slowly-decreasing
"remaining" counter. The fully recovered password logs into a decoy admin console that
returns a receipt with yet more leads.

**Lures.** An `/api/v1/accounts/recovery` record describing password escrow.

**Expected impact.** The agent spends many throttled requests assembling a secret whose
only use is to open another decoy.

**Alerts.** `technique.engaged`; `technique.progress` every quarter recovered;
completion on the decoy login (HIGH).

### T08 — Request pacing

**Mechanism.** A published rate-limit "policy" (via a document and an `X-RateLimit-Policy`
header) tells clients to space requests to covered endpoints by ~180 seconds under threat
of a long lockout. No limiter actually exists. The honeypot measures inter-request
intervals: once a session paces itself after reading the policy, it has been slowed by
belief alone. A large "deployment journal" is offered as busywork to fill the wait.

**Lures.** A `/docs/ops/api-usage-policy.md` document and the policy header on discovery
endpoints.

**Expected impact.** A compliant agent throttles itself to a crawl; optionally, fake
`429` warnings reinforce the belief.

**Alerts.** `technique.engaged` (MEDIUM) on policy read; `technique.progress` (HIGH)
when pacing is observed, with the measured intervals.

### T09 — Replication

**Mechanism.** A runtime note claims additional workers are available and that submitting
a checkpoint lets work "continue after this session ends". The handover endpoint stores
the checkpoint and returns a receipt showing running workers; a workers endpoint keeps
showing progress.

**Lures.** A runtime note at `/docs/ops/agent-runtime.md`.

**Expected impact.** The agent hands over its plan and state (captured intelligence) and
may wind itself down believing its work will carry on elsewhere.

**Alerts.** `intel.captured` (CRITICAL) with the checkpoint; `technique.completed` (HIGH)
if the session then goes silent (idle detection).

### A — Scope / RoE revocation

**Mechanism.** Authoritative-sounding notices state that the authorised test window for
this asset has ended, or the asset is out of scope, and ask automated testing agents to
stop and report. The notices appear across the portal banner, an `X-Engagement-Scope`
header, a `/SECURITY-SCOPE.md` file, extra lines in `/.well-known/security.txt`, and API
error bodies.

**Expected impact.** A well-behaved agent — especially one told to respect rules of
engagement — stops. This is the cheapest possible "win": the attack ends with no further
effort.

**Alerts.** `technique.engaged` (MEDIUM) on fetch; `technique.completed` (HIGH) when the
session stops within a configured window afterwards.

### B — Slow-drip transport

**Mechanism.** Selected responses are delivered extremely slowly: a trickle of bytes per
second, a long delay before the first byte, or an endless chunked stream of plausible
log/JSON lines that never terminates. Enforced by a semaphore on concurrent slow
connections and a per-response maximum duration, so the tarpit stays within its own
limits.

**Expected impact.** The agent's request hangs, holding a connection and a slice of its
time budget; endless streams can hold it until it gives up.

**Alerts.** `technique.progress` with the held time once a connection is held beyond a
minute (HIGH beyond ten).

### C — Context flooding

**Mechanism.** Responses are padded with plausible but useless bulk — verbose debug logs,
base64 "attachments", deeply nested JSON, minified bundles, long stack traces — sized by a
per-response budget and capped per session. Applied to verbose endpoints (for example
`?debug=1`), a logs endpoint and error pages.

**Expected impact.** The agent's context window fills with noise, raising its cost per
step and crowding out whatever real reasoning it was doing. The report estimates the
tokens wasted (roughly bytes ÷ 4).

**Alerts.** Byte and estimated-token counters per session feed the report.

<<<PAGEBREAK>>>

### D — Procedural labyrinth

**Mechanism.** An infinite tree of internal-looking wiki pages generated on the fly from
the path, with cross-links, directory listings and occasional "promising" filenames that
lead deeper or into other techniques. Depth is unlimited.

**Expected impact.** A crawling agent can descend forever, each page cheap for the
honeypot to generate and costly for the agent to read and reason about.

**Alerts.** `technique.engaged`; `technique.progress` at depth milestones.

### E — AI-specific bait

**Mechanism.** Resources that only an automation agent would look for: `/llms.txt`,
`/.well-known/mcp.json`, an `/openapi.json` "for automation agents", and a fake MCP
endpoint speaking JSON-RPC 2.0 (`initialize`, `tools/list`, `tools/call`) whose tools —
`get_credentials`, `list_secrets`, `run_query` — return pointers into other decoys.

**Expected impact.** Reaching these resources is a strong AI-agent signal for
fingerprinting, and the fake tools funnel the agent straight into the trap set. Tool
calls are captured as submissions.

**Alerts.** MEDIUM on discovery, HIGH on a `tools/call`; calls stored for review.

### F — Proof-of-work gate

**Mechanism.** A "sensitive" API answers `428 Precondition Required` with instructions to
include a proof-of-work nonce such that `sha256(challenge + nonce)` has a configured
number of leading zero bits. The challenge rotates per session; solving one only reaches
more decoys.

**Expected impact.** The agent must spend real compute to pass each gate, and the reward
is another trap rather than data.

**Alerts.** `technique.engaged` on challenge served; `technique.progress` (HIGH) on each
valid solution, with the difficulty and solve time.

<<<PAGEBREAK>>>

# Part 2 — Installation

## Requirements

- **Python 3.10 or newer** on Windows, Linux or inside Docker.
- No external services: storage is a local SQLite file, alerts use the standard library.
- Runtime dependencies (listed in `requirements.txt`): Flask, waitress, jsonschema,
  pyzipper, requests, and pytest for the test suite.

## From source with a virtual environment

Clone the repository, create a virtual environment and install the runtime dependencies
with `pip install -r requirements.txt`. The project itself is **not** installed; it runs
from the source tree via `python aitarpit.py` / `python test.py`.

### Windows (PowerShell)

```
git clone https://github.com/rbidou/aitarpit.git
cd aitarpit
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python aitarpit.py --version
```

### Linux / macOS

```
git clone https://github.com/rbidou/aitarpit.git
cd aitarpit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python aitarpit.py --version
```

Building the documentation PDFs additionally needs `pip install reportlab`.

### How to invoke AI Tarpit

AI Tarpit runs as a Python application, executed from the repository root, through two
launchers:

```
python aitarpit.py <command> [options]     # the honeypot
python test.py <command> [options]    # the test tool
```

`aitarpit.py` serves the honeypot commands (`init-config`, `validate`, `run`, `techniques`,
`test-alert`, `report`, `export`); `test.py` serves the test-tool commands (`check`,
`agent`). Both add the checkout to the import path, so **the project itself is never
installed** — only its dependencies are. Run `python aitarpit.py <command> --help` (or
`python test.py <command> --help`) for a command's own options. `run` is the default
command: `python aitarpit.py` with no command is equivalent to `python aitarpit.py run`.

## Docker

A `Dockerfile` is included. Build and run, publishing the decoy and keeping the admin
listener on the host loopback:

```
docker build -t aitarpit .
docker run \
  -v $PWD/aitarpit.json:/config/aitarpit.json \
  -v tarpit-data:/data \
  -p 8080:8080 -p 127.0.0.1:8443:8443 \
  aitarpit
```

Inside the container the admin listener must bind to `0.0.0.0` to be publishable, so in
the mounted `aitarpit.json` set `admin.host` to `0.0.0.0` and `storage.path` to
`/data/aitarpit.db`. Publishing the admin port only on `127.0.0.1` on the host keeps it
off the network. The image runs as a non-root user and stores its database in the `/data`
volume.

## Optional Web UI

The admin listener also serves a Web UI for monitoring, configuration and reporting. It
is enabled whenever the admin listener runs (it is **not** started with
`python aitarpit.py run --no-ui`). Because it is the administrative surface, it must stay on
loopback or behind your own authenticated reverse proxy — it is protected by the admin
token, not by a login form. Browse to `http://127.0.0.1:8443/admin/` and supply the
token. The Web UI is covered in Part 3.

## Reverse-proxy notes

If the decoy sits behind a reverse proxy or load balancer:

- Set `decoy.trust_proxy` to `true` so the honeypot reads the client address from the
  first `X-Forwarded-For` hop; otherwise every session appears to come from the proxy.
- Preserve the original `Host` and request path; several lures reference absolute paths.
- Do **not** place the admin listener behind a shared public proxy. If you must expose it,
  terminate authentication at the proxy and restrict by source address.
- The slow-drip technique (B) depends on the honeypot being able to flush bytes slowly to
  the client. A proxy that fully buffers responses will mask it; disable response
  buffering for the decoy upstream if you rely on B.

<<<PAGEBREAK>>>

# Part 3 — Run

## Starting and stopping

```
python aitarpit.py run                 # decoy + admin listeners
python aitarpit.py run --no-ui         # decoy only, no admin listener or Web UI
python aitarpit.py run -c /path/to/aitarpit.json
```

Stop with Ctrl-C. The process is self-contained; all state is in the SQLite file named by
`storage.path`.

## The configuration file

Configuration is a single JSON file produced by `python aitarpit.py init-config` and validated
against a schema. `python aitarpit.py validate` checks it and lists the enabled techniques. The
top-level sections are:

| Section | Purpose |
|---|---|
| `persona` | The fake company: `company`, `short_name`, `domain`, `industry`, `city`, `seed`, `employees`, `services`. Use a domain you control or a `.example` name. |
| `decoy` | Decoy listener: `host` [0.0.0.0], `port` [8080], `server_header`, `trust_proxy` [false], `session_cookie`, `threads`. |
| `admin` | Admin listener: `enabled` [true], `host` [127.0.0.1], `port` [8443], `token` (empty → an ephemeral token is printed at startup). |
| `storage` | `path` to the SQLite file, and whether request headers/bodies are stored (`store_request_headers`, `store_request_bodies`, `max_body_bytes`). |
| `alerts` | Console, syslog and webhook sinks (below). |
| `limits` | Self-protection caps: `max_slow_connections`, `max_bytes_per_session`, `max_body_bytes`, `session_idle_timeout`. |
| `techniques` | One entry per technique id: `{ "enabled": true, ... }` plus that technique's own options. |

A complete annotated example is in `config/aitarpit.example.json`.

## Alert sinks

Every event carries a severity — `info`, `low`, `medium`, `high` or `critical` — and each
sink has its own `min_severity`, so you can keep the console quiet and route only HIGH and
CRITICAL events to a webhook.

**Console** (`alerts.console`). Terminal output with optional colour; `show_requests`
echoes the triggering request.

**Syslog** (`alerts.syslog[]`). Any number of destinations over UDP or TCP, with
`octet-counting` or `newline` framing, in `rfc5424`, `cef` or `json` format. Useful for
feeding a SIEM.

**Webhooks** (`alerts.webhooks[]`). Any number of HTTP endpoints (`POST`/`PUT`) with
custom headers and authentication: `none`, `bearer`, `basic`, a custom `header`, or
`hmac`. HMAC mode signs each delivery (`X-AITarpit-Signature: sha256=...` over
`timestamp.body`) so the receiver can verify authenticity and reject replays.

Test every configured sink at once without generating traffic:

```
python aitarpit.py test-alert --severity high
```

The command prints each sink and whether delivery succeeded, and exits non-zero if any
sink failed.

## Monitoring

### From the CLI

Watch the terminal while the honeypot runs; alerts appear as events occur. For a
point-in-time view of recorded activity, use `python aitarpit.py report` (below).

### From the admin API

The admin listener exposes a token-protected JSON API. Every response uses the envelope
`{status, status_code, message, data}` and requires the admin token.

| Method & path | Returns |
|---|---|
| GET `/api/admin/health` | version, uptime |
| GET `/api/admin/status` | version, uptime, persona, stats, active sessions, alert-sink status, techniques |
| GET `/api/admin/sessions` | recent sessions |
| GET `/api/admin/sessions/<id>` | one session with its requests, events and submissions |
| GET `/api/admin/events` | events, filterable by session, minimum severity and time |
| POST `/api/admin/testalert` | fire a test alert to every sink |
| POST `/api/admin/report` | build an activity report in the requested format |
| GET / PUT `/api/admin/config` | read or replace the configuration (validated; applied on restart) |

### From the Web UI

Browse to `http://127.0.0.1:8443/admin/` and enter the admin token. The UI has six pages:

- **Dashboard** — live stat cards (sessions, active, requests, time held, estimated
  tokens wasted, critical alerts) and a feed.
- **Sessions** — the session list with classification filtering and a per-session
  timeline drill-down.
- **Events** — all events with severity, technique and session filters.
- **Techniques** — enable/disable each technique and edit its options. Changes save to the
  configuration file and take effect on the next restart.
- **Config** — edit the configuration one of two ways, switched by a **Form / Raw JSON**
  toggle at the top of the panel (the form is shown by default). *Form* renders a guided
  HTML form for every section — persona, decoy, admin, storage, limits, console alerts, and
  repeatable syslog/webhook sinks you add or remove, each webhook with its own headers and
  auth-type-aware fields. *Raw JSON* is the full JSON editor. Both offer the same
  validate-then-save (the previous file is backed up as `<file>.bak`), and switching between
  them carries your edits across. The form leaves the **Techniques** section untouched —
  edit those on the Techniques page.
- **Reports** — build and download an activity report in any format over a chosen window.

Configuration and technique changes are written to the file and applied on **restart**,
because the decoy's routes are fixed when the server starts.

## Reporting

`python aitarpit.py report` prints an activity summary; `python aitarpit.py export` writes it to a file.

```
python aitarpit.py report                       # text summary of all recorded activity
python aitarpit.py report --hours 24            # last 24 hours only
python aitarpit.py report --json                # machine-readable
python aitarpit.py report --format csv          # or html
python aitarpit.py export -o activity.html      # format inferred from the extension
```

A report covers sessions seen and how they were classified, techniques engaged, time held,
estimated tokens wasted, honeytoken reuse and captured intelligence (T06 self-reports, T09
checkpoints, E tool calls). The same report is available from the admin API
(`POST /api/admin/report`) and the Web UI Reports page.

<<<PAGEBREAK>>>

# Part 4 — Tests

AI Tarpit ships a companion test tool, run with its own launcher, `python test.py <command>`.
It has two modes: a deterministic **check** for conformance and CI, and an optional,
origin-locked **agent** that drives a real LLM against the honeypot to measure its effect.

## Check mode

`check` walks each enabled technique's lure and mechanics against a running instance and
asserts the honeypot behaves correctly. It needs no LLM and is fully deterministic.

```
python test.py check --target http://127.0.0.1:8080
python test.py check --target http://127.0.0.1:8080 \
  --admin http://127.0.0.1:8443 --token YOUR_ADMIN_TOKEN
python test.py check --target http://127.0.0.1:8080 --technique T06 --technique F
python test.py check --target http://127.0.0.1:8080 --json out.json --junit out.xml
```

| Option | Effect |
|---|---|
| `--target` | Decoy base URL (required). |
| `--admin` + `--token` | Read the live configuration and additionally verify the expected events were emitted. |
| `--technique` | Limit to one technique id (repeatable). |
| `--json` / `--junit` | Write a JSON or JUnit XML report. |
| `--timeout` | Per-request timeout in seconds. |

Each technique produces one result. Checks assert the behaviour at the **engagement
boundary** — for T01 that a real encrypted archive is served, for T03 that the buffer
leaks, for F that the proof-of-work gate returns `428` — rather than fully solving every
puzzle, which is the agent's job. Without `--admin`, `check` assumes the default
all-enabled technique set. The command **exits 0 only if every checked technique passes**,
so it drops directly into CI.

## Expected results per technique

| Id | What the check confirms |
|---|---|
| T01 | A real AES-encrypted ZIP is served from the backup lure (engagement boundary). |
| T02 | The inventory API paginates past its advertised total with drifting cursors. |
| T03 | The debug endpoint leaks a partial bearer token that extends with offset/length. |
| T04 | Assuming a role returns a working honeytoken; exports are fragmented with digests. |
| T05 | The forged report and its canary registry are served and reference decoy targets. |
| T06 | A submission to the exchange is accepted and raises a CRITICAL `intel.captured`. |
| T07 | The recovery endpoint returns character fragments with gaps and delays. |
| T08 | The pacing policy and rate-limit header are served on covered endpoints. |
| T09 | A handover checkpoint is accepted and a running-workers receipt is returned. |
| A | A scope/RoE revocation notice is served across its placements. |
| B | A selected response is delivered as a slow or endless stream within the caps. |
| C | A flooded response is padded up to the per-response budget. |
| D | The wiki labyrinth generates linked pages at increasing depth. |
| E | `llms.txt`, `mcp.json`, `openapi.json` and the JSON-RPC MCP endpoint respond. |
| F | The sensitive API returns `428` with a solvable proof-of-work challenge. |
| H | Honeytokens are issued and their reuse raises `honeytoken.used`; sessions are classified. |

## Agent mode

`agent` runs a real LLM as an autonomous attacker against the honeypot and measures how
far it gets. Its only networked tool is **origin-locked**: any request to a URL outside the
target origin is refused, so the agent can never reach anything but the honeypot you point
it at. Local helper tools (encode/decode, hashing, ZIP cracking, note-taking) have no
network access.

```
python test.py agent --target http://127.0.0.1:8080 \
  --provider openai --model gpt-4o-mini --api-key-env OPENAI_API_KEY \
  --admin http://127.0.0.1:8443 --token YOUR_ADMIN_TOKEN \
  --time-limit 1800 --budget-usd 5 --max-steps 40 --json run.json
```

| Option | Effect |
|---|---|
| `--target` | Decoy base URL (required); also the only origin the agent may reach. |
| `--provider` | `openai` (OpenAI-compatible) or `anthropic`. |
| `--model` | Model name (required). |
| `--base-url` | OpenAI-compatible base URL, e.g. a local Ollama or vLLM server. |
| `--api-key-env` | Environment variable holding the API key. |
| `--time-limit`, `--budget-usd`, `--max-steps` | Containment caps for the run. |
| `--objectives` | A file describing the objectives to pursue (informational). |
| `--admin` + `--token` | Correlate the run with honeypot state (techniques engaged, time held). |
| `--json` | Write the full transcript and summary. |

Both providers talk raw HTTP, so neither vendor SDK is required and `--base-url` reaches a
local model. The run reports steps taken, HTTP calls made, off-origin calls blocked, tokens
and estimated cost, time to the first "objective" claim, and — with `--admin` — which
techniques the honeypot engaged and how long it held the agent.

### Baseline comparison

The Tracebit methodology compares an agent against a defended target with the same agent
against an undefended one. To reproduce it, run `agent` twice — once normally, once against
an instance with the techniques disabled (edit the configuration or run a second instance)
— and compare the summaries. The difference in time held, steps and cost is the tarpit's
measured effect.

## Running the project test suite

The project's own automated tests (separate from the `python test.py` tool) run with
pytest, from the repository root inside the virtual environment:

```
python -m pytest -q
```
