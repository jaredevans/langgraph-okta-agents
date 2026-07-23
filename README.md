# Okta Multi-Agent Security Triage Pipeline

A multi-agent AI workflow that ingests Okta system logs, finds suspicious
identity activity, assesses its risk against a threat-intelligence knowledge
base, and drafts remediation plans — built on LangGraph and OpenAI
`gpt-5-mini`.

Given a large Okta system-log export in CSV form (not included in this repo —
you supply your own; the project was developed against a ~116K-row export),
the pipeline
surfaces a handful of the most suspicious users and produces, for each one, an
**incident ticket**: a reconstructed session timeline, an evidence-based
0–100 risk score with matched attack patterns, an escalate/dismiss triage
decision, and — for escalated incidents — a step-by-step containment plan.
**The system never takes action against Okta or anything else**; remediation
plans are advisory text for a human SOC analyst to review.

## How to run it

Prerequisites: [uv](https://docs.astral.sh/uv/) and an OpenAI API key.

```bash
uv sync                # installs Python 3.12 env + dependencies from uv.lock
cp .env.example .env   # then put your OpenAI API key in .env
uv run python -m okta_agents run --log path/to/your_okta_system_logs.csv
```

The log CSV is a flattened Okta System Log export (one row per event, dotted
column names). CSVs are gitignored — no log data ever ships with the repo.

### CSV fields the app reads

Of the ~59 columns in a typical export, the app uses these; all others are
ignored.

| Field | Used for |
|---|---|
| `actor.type` | Row filter: only `"User"` rows are analyzed — Okta system, app, and agent accounts are dropped |
| `actor.alternate_id` | The user's email — the grouping key for all per-user scoring; must contain `@` |
| `actor.display_name` | Human name shown in cases and incident reports |
| `timestamp` | Parsed to UTC datetime: event ordering, case windows, and the elapsed-time half of impossible travel |
| `event_type` | Drives most signals: failed-auth matching (`user.authentication.*`, `user.session.start`), MFA failures (contains `mfa`/`deny_push`), sensitive events (impersonation, privilege grants, API-token admin, factor tampering, policy changes), and the new-device email (`system.email.new_device_notification.sent_message`) |
| `outcome.result` | Failure detection — anything other than `SUCCESS` counts toward failed-auth/MFA signals |
| `client.geographical_context.geolocation.lat` / `.lon` | The distance half of impossible travel (haversine between consecutive logins) |
| `client.geographical_context.country` | Rare-country signal (< 5% of an active user's events) |
| `client.geographical_context.city` | Location context in timelines, and the datacenter test for campaigns (blank city = hosting/AWS, not a residential carrier) |
| `target0.type` / `target0.alternate_id` | Re-attributing system-logged factor sends (actor "Okta System") to the real victim |
| `client.ip_address` | Per-user grouping's IP context; the /16 (first two octets) drives campaign detection and the trusted home-network exemption |
| `client.user_agent.raw_user_agent` | Device/client context for agents (truncated to 60 chars and marked `…[truncated]`; prompts note that a cut UA is formatting, not an anomaly) |
| `display_message` | Okta's human-readable event description, included in each event line |
| `target0.display_name` | The application accessed (e.g. `Workday`) — powers the Workday new-device detection and app context in timelines |

The project `.env` is authoritative: it overrides any `OPENAI_API_KEY`
already exported in your shell, so a stale shell variable can't break runs.

Useful flags:

| Flag | Default | Meaning |
|---|---|---|
| `--max-cases N` | 5 | How many candidate users to run through the LLM pipeline |
| `--risk-threshold N` | 70 | Risk score at/above which triage escalates |
| `--limit-rows N` | all | Only read the first N CSV rows (quick smoke runs) |
| `--output DIR` | `reports/` | Where to write reports |
| `--rebuild-kb` | off | Force re-embedding of the threat-intel knowledge base |

Each run writes to `reports/<UTC timestamp>/`: one `<case_id>.json` (machine-
readable incident ticket) and one `<case_id>.md` (human-readable report) per
case, plus a `summary.md` index table. Case ids carry the user's full name
(`case-001-jared-evans`). Reports are written **one at a time as each
case finishes** (and `summary.md` refreshes), so you can read results during a
long run instead of waiting for the end. Each Markdown report's Risk
Assessment opens with a plain-language **Summary** line derived from the
pre-filter signals (e.g. "Part of a detected MFA attack campaign from a
hosting IP block; Impossible travel between consecutive logins"), and
`summary.md` ends with an **Issues found across all cases** rollup — each
issue type with the count and list of cases it appeared in, followed by a
plain copy/paste list of all flagged email addresses. Progress and
every agent's decision are logged to the console as the run proceeds; the exit
code is 1 if any case errored, else 0.

Optional observability: set `LANGSMITH_TRACING=true` and `LANGSMITH_API_KEY`
in `.env` and LangChain automatically traces every agent step to LangSmith —
no code changes needed.

## How it works

The pipeline is a two-stage funnel: cheap deterministic filtering first, LLM
reasoning only on what survives.

### Stage 1 — deterministic pre-filter (no LLM, no cost)

`okta_agents/prefilter.py` loads the CSV with pandas, keeps only real user
activity (`actor.type == "User"` — Okta system/app accounts are dropped), logs
how many distinct users the file contains, and scores every user on seven
heuristics:

- **Failed-authentication bursts** — non-SUCCESS auth/session events (weight 0.3 each)
- **MFA denials/failures** — failed MFA challenges and push denials (weight 0.5;
  these also count as failed auth, deliberately, since failed MFA is stronger
  compromise evidence)
- **Impossible travel** — consecutive logins whose geo distance implies
  > 800 km/h over > 500 km (weight 2.0 per pair)
- **Rare countries** — a country contributing < 5% of an active user's events (weight 1.0)
- **Sensitive events** — impersonation, privilege grants, API-token admin
  actions, MFA factor tampering (weight 1.0)
- **Workday new-device sequence** — a failed auth *any time earlier* in the
  log (even hours before), then a new-device email notification, then a
  successful Workday SSO **within 7 minutes of that email** (weight 3.0).
  Only the email→Workday gap is time-boxed. Treated as near-confirmed account
  takeover: matching users are *always* selected as cases, independent of
  `--max-cases`.
- **Shared-IP MFA campaign** (weight 3.0) — detects an attacker who holds
  stolen passwords and works through accounts from cloud infrastructure,
  trying to defeat MFA. Two phases:
  - **Qualify** a /16 IP block (first two octets) when **3+ distinct users**
    receive MFA factor sends (`send_factor_verify_push`,
    `send_factor_verify_message`/SMS) or device/MFA-enrollment events from it
    within a **24-hour window**.
  - **Sweep:** once qualified, **every identifiable user active from that
    block anywhere in the file** is flagged — a clean login from a confirmed
    attack block is the attacker using a compromised password, so it counts
    even when that user's own timeline shows no anomaly.
  Three filters keep this precise:
  - **Datacenter-only.** A block must be hosting/datacenter space, where
    attackers run tooling — not a residential/mobile carrier where employees
    legitimately live. Datacenter IPs geolocate with **no city**; carriers
    resolve to real cities. A block qualifies only if ≥70% of its events have
    a blank city — this ignores every consumer ISP at once.
  - **Org-network exemption.** Any /16 carrying >10% of all user events is the
    org's own campus/VPN egress (broad exports only).
  - **Member cap.** A qualified block with >15 members is shared
    infrastructure, not a targeted list, and is dropped.
  Okta logs factor sends under a system principal with the victim in
  `target0`; these are re-attributed to the victim so they count under the
  right person. Narrow query files (one suspect prefix an analyst already
  scoped) keep whole-file membership semantics and skip the datacenter/org
  filters. Every flagged user is *always* selected as a case.

**Trusted home networks.** IP blocks the organization owns
(`HOME_NETWORK_PREFIXES` in `prefilter.py` — e.g. `134.231` campus and
`192.26` VPN/egress) are on-site employees/students: honest by definition.
Their events are excluded from the activity-based signals (failed auth, MFA,
Workday sequence, sensitive events) and can never form a campaign attack
block — but they remain the honest anchor for impossible travel, so an attack
login paired against a campus login is still caught. Note a trusted block can
geolocate with a blank city (looking like a datacenter), which is exactly why
it must be listed explicitly rather than inferred.

Shared/service-style accounts (email prefixes `gts.`, `oktaprod.`, `hd.`) are
excluded from selection — their multi-operator usage produces false
impossible-travel and auth-failure signals (`IGNORED_USER_PREFIXES` in
`prefilter.py`).

The top-scoring users (up to `--max-cases`, plus any always-select
Workday-sequence and campaign matches) become `CandidateCase`s: the user's
most recent events (capped at 75 so prompts stay bounded) plus the signal
evidence that flagged them. Each event carries timestamp, event type,
outcome, IP, geo, user agent, and the accessed application
(`target0.display_name`) — all visible to the agents.

### Stage 2 — five-agent LangGraph pipeline (per case)

Each case flows through a LangGraph `StateGraph` whose nodes are five
specialized LLM agents, each with its own role/backstory system prompt and a
strict Pydantic output schema (via `with_structured_output`, so malformed
output fails validation instead of propagating):

```
ingest ──> analyze ──> assess ──> triage ──┬─ escalate ──> remediate ──> report
                          ▲                └─ dismiss ───────────────--> report
                          │
              ChromaDB threat-intel KB (RAG)
```

1. **Okta Telemetry Ingestion Worker** (`agents/ingestion.py`) — validates the
   event bundle: totals, time range, data-integrity problems (blank IPs,
   missing geo), notable facts. No judgments.
2. **Security Event Analyst** (`agents/event_analyst.py`) — reconstructs a
   chronological timeline, marks each entry normal/suspicious/critical, and
   lists concrete anomalies.
3. **Threat Intelligence Specialist** (`agents/threat_intel.py`) — retrieves
   the most relevant excerpts from the knowledge base (`kb/*.md`, embedded
   into a local ChromaDB collection) and matches the anomalies against known
   attack patterns — password spray, MFA fatigue, impossible travel, session
   hijacking, token abuse — assigning an evidence-based risk score 0–100.
4. **Incident Triage Coordinator** (`agents/triage.py`) — the gatekeeper:
   escalates or dismisses against the risk threshold, weighing benign
   explanations (VPNs, mobile geolocation drift) and stating business impact.
   This is a real conditional edge in the graph — dismissed cases skip
   remediation entirely.
5. **Incident Remediation Executor** (`agents/remediation.py`) — for escalated
   incidents only, drafts an ordered containment plan following the playbooks
   in `kb/remediation-playbooks.md` (suspend account, clear sessions, revoke
   tokens, ...). **Advisory only — nothing is executed.**

Shared state moves through the graph as a typed dict checkpointed with
LangGraph's `InMemorySaver` (one thread per case). A failing case produces an
error ticket and the run continues (per-case isolation).

### Which, how, and when the agents are used

Agent execution is **deterministic, not agent-chosen**. There is no
supervisor LLM deciding who runs next: the LangGraph `StateGraph`
(`okta_agents/graph.py`) hard-wires the order, and the only branch point is
the triage decision. That makes runs predictable, debuggable, and
cost-bounded — the LLMs judge *content*, never *control flow*.

| Agent | Runs when | Reads from state | Writes to state |
|---|---|---|---|
| 1. Ingestion Worker | Always, first, once per case | the `CandidateCase` (events + pre-filter signals) | `ingestion` report |
| 2. Security Event Analyst | Always, after ingestion | case events + `ingestion` | `timeline` (+ anomalies) |
| 3. Threat Intel Specialist | Always, after analysis | `timeline`, case signals, **+ RAG**: top-4 KB sections retrieved using the timeline's anomalies as the query | `risk` (score 0–100, matched patterns) |
| 4. Triage Coordinator | Always, after assessment | `risk`, anomalies, the `--risk-threshold` | `triage` (escalate / dismiss) |
| 5. Remediation Executor | **Only if triage says escalate** | `risk`, triage rationale, **+ RAG**: playbook sections retrieved by matched pattern names | `remediation` plan |

Mechanics of every agent call:

- **One LLM call per agent per case** (`gpt-5-mini`), so a dismissed case
  costs exactly 4 calls and an escalated one exactly 5.
- Each call carries a fixed **role + backstory system prompt** (from the
  project spec) plus the state fields above rendered as text — agents never
  see raw CSV, only the normalized event lines and prior agents' structured
  outputs.
- Output is forced into a **Pydantic schema** with
  `with_structured_output()`; a malformed response is a validation error
  (retried, then failing just that case), never silently propagated.
- The escalate/dismiss branch is a **conditional graph edge** evaluated in
  code from the `triage.decision` field — dismissing genuinely skips the
  remediation agent rather than prompting it to "do nothing".
- Agents run **only for candidate cases**: users the Stage-1 pre-filter
  scored at zero (or on the ignore list) never reach any LLM.
- If any agent call fails after retries, that case becomes an error ticket
  and the remaining cases still run (per-case isolation).

### The knowledge base

`kb/` holds eleven authored Markdown docs: ten Okta attack patterns (password
spray, MFA fatigue, impossible travel, session hijacking, token abuse,
new-device takeover, privileged-activity abuse, payroll/HR fraud, help-desk
reset abuse, shared-IP multi-account MFA campaigns) with indicators, risk-scoring guidance, and false-positive
notes, plus a remediation playbook. On first run they are split into
sections, embedded with
OpenAI `text-embedding-3-small`, and stored in a persistent local Chroma
collection (`chroma_db/`); a content fingerprint makes rebuilds automatic when
the docs change (or force one with `--rebuild-kb`).

## Project layout

```
okta_agents/
  config.py        # .env loading, Settings (model, thresholds, caps, paths)
  models.py        # Pydantic schemas: OktaEvent, CandidateCase, agent outputs,
                   #   IncidentTicket
  prefilter.py     # Stage-1 pandas heuristics -> CandidateCases
  knowledge_base.py# kb/*.md -> persistent Chroma collection (idempotent)
  agents/          # the five agent node factories + shared PipelineState
  graph.py         # StateGraph wiring + conditional triage edge
  report.py        # JSON + Markdown incident report writers
  runner.py        # orchestration: prefilter -> per-case graph -> reports
  __main__.py      # CLI entry point
kb/                # authored threat intel + playbooks (the RAG corpus)
tests/             # 64 offline tests (fake LLM/retriever) + 1 live smoke test
```

## Tests

```bash
uv run pytest -m "not live"   # fast, fully offline (fake LLMs/retriever)
uv run pytest -m live         # one real end-to-end case against the OpenAI API
```

The offline suite covers the pre-filter heuristics, schema validation, both
graph paths (escalate and dismiss), per-case failure isolation, and report
rendering. The live test runs one real case end-to-end (~2 minutes, a few
cents of API usage) and is skipped automatically when no API key or log CSV is
present.

## Security notes

- The OpenAI key lives only in `.env` (gitignored, never committed).
- Log data (`*.csv`), generated reports, and the Chroma store are gitignored.
- The pipeline is read-only with respect to Okta: it has no Okta credentials
  and makes no calls to any admin API. Remediation output is text for humans.

## Why these technologies

**LangGraph** (orchestration) — the workflow is a state machine, and LangGraph
is the only mainstream framework that models it as one: agents are nodes, the
escalate/dismiss decision is a first-class *conditional edge*, and shared
state is typed and checkpointed (`InMemorySaver`, one thread per case).
The alternatives were considered and rejected for this shape of problem:
**CrewAI**'s role/task model runs agents in sequence but gives weak control
over branching (we'd be prompting an LLM to "skip remediation" instead of
never invoking it), and **AutoGen**'s conversational round-robin is
non-deterministic by design — wrong for a security pipeline where
auditability and bounded cost matter more than emergent behavior.

**LangChain / langchain-openai** (LLM plumbing) — provides
`with_structured_output()`, which binds a Pydantic schema to the model call
so every agent's answer is validated JSON or a hard error. Also gives free
env-gated LangSmith tracing and a swappable model interface (changing
`model` in `config.py` is the only step to try a different OpenAI model).

**OpenAI `gpt-5-mini`** (the reasoning engine) — per-case cost is 4–5 calls,
and triage quality depends more on evidence synthesis than raw model size; a
mini-tier reasoning model handles timeline reconstruction and rubric-based
scoring well at a fraction of frontier-model cost. `text-embedding-3-small`
for the same reason: the KB is small and topically distinct, so retrieval
quality saturates cheaply.

**Pydantic v2** (data contracts) — five agents hand structured data to each
other; Pydantic makes every hand-off a validated schema (`risk_score` is
`ge=0, le=100`, decisions are `Literal["escalate","dismiss"]`), so a
hallucinated field shape fails loudly at the boundary instead of corrupting
a downstream prompt.

**ChromaDB + langchain-chroma** (RAG store) — the threat KB is ~36 sections;
it needs a local, persistent, zero-service vector store, not a managed cloud
DB. Chroma persists to disk (survives runs, content-fingerprint rebuilds),
whereas FAISS is in-memory-first and Pinecone would add a network dependency
and credential for no benefit at this scale.

---

