# Quickstart

AI Tarpit is a honeypot that **wastes the time and budget of autonomous AI attack
agents**. It presents an ordinary-looking corporate intranet whose every interesting
lead is a trap: forged secrets that unlock nothing, data streams that never end, and
documents that quietly instruct an agent to stop. This guide takes you from nothing to a
running tarpit and a first alert in a few minutes.

You need **Python 3.10 or newer**. Everything runs from one process and a single JSON
configuration file. No database server, no message broker, no cloud account.

---

## 1. Install

Clone the repository, create a virtual environment and install the runtime dependencies.
The project itself is **not** installed — it runs straight from the checkout.

### Windows (PowerShell)

```
git clone https://github.com/rbidou/aitarpit.git
cd aitarpit
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Linux / macOS

```
git clone https://github.com/rbidou/aitarpit.git
cd aitarpit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` pulls in Flask, waitress, jsonschema, pyzipper, requests and pytest.
To confirm everything is ready:

```
python aitarpit.py --version
```

The honeypot runs through `python aitarpit.py <command>`, executed from the repository root
(commands: `init-config`, `validate`, `run`, `techniques`, `test-alert`, `report`,
`export`). The companion test tool has its own launcher, `python aitarpit-test.py <command>`
(commands: `check`, `agent`). There is no `pip install` of the project itself — both
launchers import straight from the checkout.

---

## 2. Create a configuration

Generate a complete configuration file with a fresh, random admin token:

```
python aitarpit.py init-config
```

This writes `./aitarpit.json`. Open it and set at least the **persona** — the fake
company the decoy pretends to be. Use a domain you control or a reserved `.example`
name; never impersonate a real organisation.

Validate the file at any time:

```
python aitarpit.py validate
```

List the techniques and whether each is enabled:

```
python aitarpit.py techniques
```

---

## 3. Run

Start the honeypot:

```
python aitarpit.py run
```

`run` is the default command, so `python aitarpit.py` on its own starts the honeypot too.

Two listeners come up in one process:

| Listener | Default bind | Purpose |
|---|---|---|
| Decoy | `0.0.0.0:8080` | The fake intranet attackers reach. |
| Admin | `127.0.0.1:8443` | Monitoring, reporting and the Web UI (loopback only). |

The decoy must be reachable by the traffic you want to trap; the admin surface should
stay on loopback (or behind your own access control). To run without the admin
listener, use `python aitarpit.py run --no-ui`.

Open `http://127.0.0.1:8080/` in a browser: you will see the decoy intranet. Try a lure,
for example `http://127.0.0.1:8080/.env`.

---

## 4. See your first alert

Alerts print to the terminal by default. The quickest way to prove the pipeline end to
end is the built-in test alert, which fires one event to every configured sink (console,
syslog, webhook):

```
python aitarpit.py test-alert --severity high
```

Then generate real activity by poking a lure, and read a summary of what the tarpit has
recorded:

```
python aitarpit.py report
```

`report` prints a human-readable activity summary: sessions seen, how each was
classified (human / scanner / AI agent), techniques engaged, estimated time held and
tokens wasted. Add `--json`, `--format csv` or `--format html` for other formats, or
`--hours N` to limit the window. Use `python aitarpit.py export -o report.html` to write it to a
file.

---

## 5. Check that it works

AI Tarpit ships with its own test tool, run as `python aitarpit-test.py <command>`. The **check**
mode walks every enabled technique's lure and mechanics and asserts the honeypot behaves
correctly. Point it at a running instance:

```
python aitarpit-test.py check --target http://127.0.0.1:8080 --admin http://127.0.0.1:8443 --token YOUR_ADMIN_TOKEN
```

Passing `--admin` and `--token` reads the live configuration and additionally verifies
that the expected alert events were emitted. The command exits `0` only if every checked
technique passes, so it drops straight into CI.

Your admin token is the `admin.token` value in `aitarpit.json` (or, if you left it empty,
the ephemeral token printed when the honeypot starts).

---

## 6. Where to go next

- **Reference Manual — Part 1 (Concepts):** what each technique does and why it stalls an
  AI agent.
- **Part 2 (Installation):** Docker, the optional Web UI, and reverse-proxy notes.
- **Part 3 (Run):** the full configuration reference, alert sinks, monitoring and
  reporting from the CLI and the Web UI.
- **Part 4 (Tests):** the test tool in depth, including the optional
  origin-locked LLM attacking agent and the expected result of each technique.

## Safety in one paragraph

AI Tarpit is **passive**: it never connects back to an attacker, never serves real
malware and never "hacks back". Every credential, token and archive it hands out is a
**synthetic honeytoken** that grants access to nothing. The admin surface is isolated on
loopback behind a token, and the optional LLM test agent is hard-restricted to the
single target you give it. Run it only against traffic you are authorised to trap.
