# Make the record usable: install without uv, name the leaks, filter the view, export the evidence

Labels: ready-for-agent

## Problem Statement
`capture-gaps` made the capture complete; `audit-hardening` made the recorder
trustworthy. Neither helped a person *read* the record, or *install* the tool without
already being a Python developer.

- **Install assumes uv.** `install.sh` bootstraps it by piping `astral.sh/uv/install.sh`
  into `sh` as root — a step the script's own header calls an unchecksummed trust
  boundary — and a user running the documented one-liner on a machine with no Astral
  toolchain could not get netmon installed.
- **The record does not say what leaked.** netmon writes `dns.jsonl` / `http.jsonl` /
  `flows.jsonl` and expects the reader to already know that a cleartext POST, or an EDNS
  Client-Subnet record, is a disclosure. There is no severity anywhere in the tool.
- **The dashboard filter is one-at-a-time.** `f` cycles a single substring through
  `all → dns → tls → http → flow`. Four of the twelve kinds in `KIND_TO_FILE` — `arp`,
  `icmp6_ra`, `llmnr`, `nbns` — cannot be selected at all, and "DNS *and* TLS", or "only
  internet-bound", cannot be expressed.
- **The evidence is JSONL only.** Handing a run to someone who lives in a spreadsheet
  means writing a converter by hand.

## Solution
Four independent tracks, one audience — the operator who did not write this tool.

1. **Install without uv.** A checked-in, hash-pinned `requirements.txt` exported from
   `uv.lock`, and an installer that picks a builder: uv when present, the system Python
   plus pip when not, and the uv bootstrap only when nothing else can supply a ≥3.13
   interpreter. Reaching `astral.sh` becomes a last resort instead of a precondition.
2. **Leak findings.** A deterministic, stateless assessment of what each recorded event
   *discloses*, surfaced as a severity-ranked panel in the dashboard, a rollup in
   `summary.json`, and a `netmon audit` command that re-reads any recorded run.
3. **Multi-select filter.** One `EventFilter` value object over three closed vocabularies
   — kind, direction, scope — shared by the live feed *and* `netmon query`, driven from a
   checkbox bar in the TUI.
4. **CSV export.** `netmon query --format csv`, projecting the same five columns the
   dashboard shows, with the formula-injection guard a spreadsheet demands.

## User Stories
1. As an operator with no uv on my machine, I want `install.sh` to use the Python I already
   have, so that installing netmon does not require me to first install a toolchain I have
   never heard of.
2. As an operator who declines to pipe an unchecksummed script into `sh` as root, I want a
   `--pip` flag, so that I can install netmon without accepting that trust boundary.
3. As an operator on a host with only Python 3.11, I want the installer to tell me exactly
   what is missing and how to fix it, so that I am not left reading a `SyntaxError`.
4. As an operator who installed via pip, I want `netmon update` to keep working, so that I
   am not stranded on the version I first installed.
5. As a packager, I want `requirements.txt` to be provably in step with `uv.lock`, so that
   the pip path can never silently install a different dependency tree than the uv path.
6. As an operator reading a run, I want each event rated by what it *discloses*, so that I
   can tell a cleartext credential POST apart from a routine DNS lookup.
7. As an operator, I want the diagnosis to say what leaked, to whom, and what I can do
   about it, so that a finding is actionable rather than merely alarming.
8. As an operator, I want findings aggregated by subject with a count, so that plaintext
   DNS to one resolver is one line reading `×1,432` and not 1,432 lines.
9. As an operator whose laptop talks to itself constantly, I want loopback traffic to never
   be called a leak, so that the panel is worth reading on day one.
10. As an operator, I want an ECS record advertising a `/0` prefix to be recognised as a leak
    *prevented*, so that the tool does not invert the truth it exists to report.
11. As an operator running the headless recorder, I want the findings rollup in
    `summary.json`, so that the always-on unit — which has no dashboard — still reports them.
12. As an auditor, I want to run `netmon audit` against a run recorded *before* this feature
    existed, so that the evidence I already hold is not wasted.
13. As an auditor, I want severity recomputed from the record rather than frozen into it, so
    that improving a rule re-assesses every historical run for free.
14. As an operator, I want to see DNS *and* TLS at once, so that I can watch a name being
    resolved and then connected to.
15. As an operator, I want to filter to internet-bound events only, so that I can ignore the
    LAN chatter that dominates a home network.
16. As an operator, I want `arp`, `icmp6_ra`, `llmnr` and `nbns` to be selectable, so that
    the four kinds netmon records but never let me filter to stop being invisible.
17. As an operator, I want the same filter vocabulary in `netmon query` as in the dashboard,
    so that what I learn in one is transferable to the other.
18. As an operator, I want `--scope internet` to mean every internet-bound event, not just
    flows, so that the DNS query and the SNI — which *are* the disclosure — are included.
19. As an operator who unchecks every kind, I want an empty feed and a clear message, so that
    the tool never silently reinterprets what I asked for.
20. As an operator, I want the active filter named in the feed's border, so that a filtered
    view can never be mistaken for a quiet network.
21. As an operator who filters while scrolled back, I want the frozen snapshot re-filtered
    rather than the live tail, so that the view under my cursor does not jump.
22. As an auditor, I want `netmon query --format csv`, so that I can open a run in a
    spreadsheet without writing a converter.
23. As an auditor, I want a hostile DNS name beginning `=` to arrive in my spreadsheet inert,
    so that opening the export cannot run a command on my machine.
24. As an auditor, I want `--min-severity` to compose with `--format csv`, so that one command
    gives me a spreadsheet of exactly the leaks from an overnight recording.
25. As an auditor, I want the CSV to state plainly that it is the dashboard's view and the
    JSONL is the evidence, so that I do not mistake a lossy projection for the record.

## Implementation Decisions

### Naming
The feature is **leak findings**, never "alerts" or "suspicious packets". README's
*What this tool does NOT show you* disclaims threat detection; every noun here says
*disclosure*, never *threat*. This is not cosmetic — it is what keeps the feature inside
the tool's honest bound.

### Leak findings
- **North-star invariant: a rule may only claim what the event's own fields prove.** This
  bans the IDS shapes (baselines, novelty, beaconing, rare ports) *and* bans over-claiming.
- `assess(event) -> Finding | None` is a **fourth projection** beside `event_direction` /
  `event_host` / `event_detail`: same `match event.kind` dispatch, never `isinstance`.
  Exactly one finding per event, so a packet can never double-count.
- `Severity` (low/medium/high) and `Rule` are `StrEnum`s; `Finding` is a `NamedTuple`
  carrying `rule`, `severity`, `subject` (the aggregation key), and a three-part diagnosis
  — `leaked` (what crossed the wire), `to` (whom), `advice` (what to do). Pydantic is
  reserved for wire events; a `NamedTuple` is the codebase's signal for a pure value object.
- **`StrEnum` compares lexically** (`"high" < "low"`), so every severity comparison goes
  through `SEVERITY_RANK`. A bare `>=` is a silent bug.
- **Findings are never persisted per-event.** The JSONL stays raw evidence; findings stay
  recomputable interpretation. The *rollup* goes to `summary.json`, which is already the
  home of derived interpretation (`top_dns_names`, `coverage`). Consequence: improving a
  rule re-assesses every historical run, including runs recorded before the feature existed,
  because `EVENT_ADAPTER` already reparses old JSONL into typed events. No schema change, no
  migration, no drift.
  - Rejected: an `AlertEvent` kind. `_tally` does `event_counts[kind] += 1` and
    `coverage.mark("event")`; an alert is not a packet that disclosed something, it is a
    statement *about* one. It would double-count both ledgers and freeze the assessment at
    capture time.
  - Rejected: a `severity` field on every event. Touches all 12 models, is `None` for most,
    and would still need the function to explain *why* — a second, drifting authority.
- A bounded `FindingLedger` owned by `PacketProcessor` aggregates by `(rule, subject)` with a
  count, tallied in the **single existing walk** in `_tally()`. That is the whole integration:
  `consume()`, `Writer`, `JsonlWriter`, `KIND_TO_FILE` and `DashboardModel` are untouched, and
  findings are tallied identically under TUI, headless, replay and the systemd recorder. Its
  `evicted` counter lands in the coverage ledger — a bounded table owes the same honesty here
  as every other one.

### The rules
`scope` below is `remote_scope(peer)`. A new `SERVICE_LEAK` table sits beside `SERVICE_NOTES`,
which stays the one authority for the *prose*; `SERVICE_LEAK` is the one authority for the
*severity*.

| Rule | Trigger | Severity | Subject |
|---|---|---|---|
| `cleartext-http` | any `HttpEvent`, except loopback | HIGH on POST/PUT/PATCH; LOW if `tag=captive-portal`; else MEDIUM. Demoted one level on lan/linklocal | host |
| `cleartext-dns` | `dns_query` to internet/cgnat → MEDIUM; lan → LOW; loopback → none | | the **resolver** |
| `internal-name-escaped` | `dns_query` to internet for a `.local`/`.internal`/`.home.arpa`/single-label name, or a private-address PTR | HIGH | qname |
| `mdns-broadcast` | `dns_query` to a multicast peer | LOW | the **device** |
| `lan-name-broadcast` | `llmnr` / `nbns` | MEDIUM | qname |
| `wpad-broadcast` | `llmnr`/`nbns` for a `wpad*` name | HIGH | qname |
| `ecs-subnet` | `dns_ecs` whose prefix length is **> 0** | MEDIUM | client_subnet |
| `plaintext-service` | `flow` whose `service` is in `SERVICE_LEAK` | ftp HIGH; smtp/imap/pop3 MEDIUM; ntp/http LOW; demoted off the internet | service + host |

**The false-positive killers are the design**, not a refinement of it:
- **Loopback is never a leak.** The repo's own fixture is a `127.0.0.1` Syncthing REST call;
  flagging it would destroy trust in the panel immediately.
- **ECS with `plen == 0` is a leak prevented** — the resolver explicitly told the
  authoritative side *do not use my client's subnet*. Flagging it inverts the truth.
- **Aggregation by subject** is what makes the highest-volume true finding readable.

**Rejected rules, deliberately:** cleartext TLS SNI (fires on ~every flow, and `tls.jsonl`
*is already* the cleartext-SNI record — shipped instead as `tls_sni_cleartext` /
`tls_sni_ech` counters giving an honest ECH-coverage figure); HTTP User-Agent (same packet
as `cleartext-http`, so a second rule would double-count one disclosure); `ech=false` in an
HTTPS RR (that is the *site's* posture, not your leak); ARP and ICMPv6 RA (the network
telling *you* things, not your disclosure). Noted for a future *posture* layer, not this
one: "DNS offered ECH but the TLS hello did not use it" — genuinely valuable, but it needs
cross-event state and so breaks the stateless invariant.

The mail rules must not over-claim: netmon never reads the SMTP/IMAP payload and so cannot
know whether the client upgraded with STARTTLS. The diagnosis says so — which is why they are
MEDIUM, not HIGH.

### Filter
- **Prefactor first.** `scope` exists only on `FlowEvent` today, and `_event_matches` reaches
  it with `getattr(ev, "scope", None)` — the only field-existence dispatch in the tool. Make
  the projections **total** over all 12 kinds: `event_remote_addr`, `event_scope`,
  `event_direction_name`. Every kind does have a usable peer address (`dst` / `resolver` /
  `remote_ip` / `target_ip` / `router`), so this invents no values. `event_direction` becomes
  a glyph lookup over `event_direction_name`, and the existing glyph assertions must pass
  untouched — that is the proof the prefactor is behaviour-preserving.
- One frozen `EventFilter` dataclass over three closed vocabularies: **OR within a dimension,
  AND across dimensions**. Defaults are the full vocabulary, so "unset" needs no special case
  and a checkbox group maps 1:1 onto a set. `host` is a substring of `event_host()`, with `""`
  as the identity.
- **No boxes checked means an empty feed** — honest ("I selected zero kinds"), signposted in
  the border title and the placeholder, never silently reinterpreted as "all".
- `DashboardModel.passes()` survives as the seam and delegates. **`_event_matches` is deleted.**
- `netmon query` gains repeatable `--kind` / `--direction` / `--scope`, all with `choices=`.
  Two deliberate breaking changes: `--scope internet` now matches every kind whose peer is on
  the internet, not just flows; and `--scope local` is rejected with the valid choices, because
  `local` is a **direction**. (The existing query fixture records `FlowEvent(scope="local")` — a
  value `remote_scope` can never return. The unification surfaces that the fixture is fibbing.)
- Dropping the TUI's substring match is a **zero-capability loss**: all four current needles are
  kind names, so the host/detail arms are unreachable-in-practice accidents.

### The filter widget
An **in-place collapsible bar**, not a modal. Textual's `App.children` is only the active
screen, so while a `ModalScreen` is pushed `query_one("#feed")` raises `NoMatches` — the 10 Hz
`_render` would early-return for the modal's whole life and the pending-event list would pile
up. A `FilterBar` above the feed changes the feed's **height**, never its width, so the column
fitting is untouched. Three `SelectionList`s, one per dimension.

The `escape` collision (already bound to *follow*) dissolves for free: Textual resolves bindings
along `focused.ancestors_with_self`, so binding `escape` on the bar shadows the App's binding
only while focus is inside the bar. `SelectionList` does not override `check_consume_key`, so
`f` still reaches the App and opens *and* closes the bar.

Two new text sinks — `Selection` prompts and `border_title` — both markup-parse a `str`, so both
take a `Text`. The markup-injection guard extends rather than breaks.

### CSV
`event_to_cells` **already is** the CSV row — the one presentation projection, already scrubbed,
already the dashboard's authority, already tested per kind. `--format csv` re-serialises it, with
the full ISO timestamp instead of the feed's `HH:MM:SS` slice (an exported run spans midnight and
gets sorted in a spreadsheet). The header is a *projection*, not a schema: a new event kind adds
rows, never columns.

Lossy, and honest about it: **CSV is the dashboard's view; the JSONL is the evidence.** A lossless
per-kind mode (`--format csv --kind X` emitting that model's exact columns) is coherent but forces
twelve invocations to see one run — deferred, not built.

**A spreadsheet is an interpreter too.** Excel and LibreOffice evaluate any cell beginning
`= + - @`, and netmon records attacker-controlled DNS names and HTTP paths verbatim. `csv_cell()`
sits beside `printable()` and takes the same posture — map, never drop — prefixing a leading
apostrophe, the spreadsheet's own literal-text marker, so the original character stays visible.
`printable()` runs first, so a cell can never contain a newline: a row is always one physical
line, and the file stays greppable and safe to `cat`.

### Install
- `requirements.txt` is **generated**, with hashes, covering the `tui` extra (`netmon run` *is*
  the dashboard, so a tui-less install is a broken one-liner). `pip install --require-hashes`
  then gives the same integrity guarantee as `uv sync` — which matters most to the person who
  declined the unchecked download in the first place.
- The installer picks a builder: `--pip` forces pip; otherwise uv when present; otherwise the
  system Python if it satisfies `requires-python` **and** can build a venv (Debian splits
  `ensurepip` into `python3-venv` — a host with 3.13 but no venv module must not be selected and
  then fail obscurely); otherwise the uv bootstrap; otherwise die with a message naming what was
  found and what to install.
- The pip venv **must** use `python3 -m venv --copies`. A symlinked venv's `bin/python3` resolves
  into `/usr/bin/python3.x`, where `maybe_setcap` correctly refuses to arm raw sockets — so
  without `--copies` the pip path silently loses passwordless capture. While there, replace
  `maybe_setcap`'s `/usr/*` blocklist with a `$NETMON_DIR/*` allowlist (the actual invariant) and
  smoke-test the armed interpreter before trusting it, since a file capability puts the loader in
  secure-execution mode.
- **`netmon update` is the real coupling** and must learn the pip path *before* that path ships,
  or a pip install is stranded on the version it was installed at. The builder is derived from the
  venv itself — `uv sync` does not seed pip into the venv it creates, so `.venv/bin/pip` existing
  is an authoritative "the pip path built this".

## Testing Decisions
A good test states what was on the wire and asserts the disclosure that must surface — never how
the code is arranged. Test through the **highest** seam: `PacketProcessor.process(pkt)` with scapy
packets built in-process, as `capture-gaps` established.

- **Rules** are driven through `process(pkt)` and asserted on the emitted event's `assess()` and on
  `summary()["findings"]`. Every rule ships with its **negative** — the loopback HTTP call that is
  *not* a leak, the `/0` ECS that is a leak prevented.
- **Pure projections** (`assess`, `EventFilter.matches`, `csv_cell`, `event_to_csv_row`) are tested
  directly as plain Python, Textual-free.
- **The TUI** is driven through Textual's `run_test()` pilot with the existing `FakeCapture`.
- **Drift guards**, in the idiom the repo already uses for `KIND_STYLE` vs `KIND_TO_FILE`: the
  projections are total over `KIND_TO_FILE`; every `Rule` is reachable from `assess()`;
  `SERVICE_NOTES ⊆ SERVICE_LEAK ⊆ SERVICE_BY_PORT.values()`; `requirements.txt` agrees with
  `uv.lock` and `pyproject.toml`; `install.sh`'s Python floor agrees with `requires-python`. There
  is no CI — pytest *is* the gate, so every drift guard is a test.
- The module-copy test (`TestRenderHelpersAcrossModuleCopies`) is extended to the new projections:
  they must dispatch on `.kind`, never `isinstance`. The codebase has already been bitten by this.

Invariants that must survive, each already covered: `add_event` never drops, so the ring is
filter-independent and re-checking a box re-reveals; filtering while frozen re-filters the
**snapshot**, not the live tail; a filter that empties the feed clears the stale detail pane; the
filter is **display-only** and never reaches the `Writer` or the pcap sink; `_paint` stays the only
`Static.update` call site.

Prior art: `TestServiceAnnotations`, `TestEventToCells`, `TestEventDirection`,
`TestDashboardModelFilter`, `TestKindStyle`, `TestRenderHelpersAcrossModuleCopies`,
`TestNetmonQuery`, `TestCoverageLedger`, `TestSilentDropHonesty`, `TestBoundedCounter`,
`TestLruSet`, and in `test_tui.py` `TestNetmonAppFeed` and `TestNetmonAppHostileText`.

## Out of Scope
Everything the README already disclaims stands: traffic-analysis statistics, JA3/JA4
fingerprints, the IPv6 EUI-64 MAC-derivation flag, decryption needing session secrets. Added
here:

- **Any behavioural or anomaly detection** — baselines, first-seen destinations, beaconing
  intervals, rare-port heuristics, volume thresholds. netmon has no notion of "unusual" and will
  not grow one. A quiet findings panel means *no known-shape disclosure was recorded*, not that
  nothing leaked.
- **A live CSV recorder.** JSONL is the evidence; CSV is an export from it.
- **Lossless per-kind CSV** (`--format csv --kind X`). Coherent, deferred until someone asks.
- **A free-text search box in the TUI.** `EventFilter.host` exists and is exercised by `query`;
  wiring an `Input` into the dashboard is a later slice.
- **Persisting the filter across restarts.** netmon has no config or state file; run dirs are its
  only output. A filter dotfile would be the first persistent state in the tool.
- **`requirements-dev.txt`.** The contributor gate is `uv run pytest/ruff/mypy`; a dev
  requirements file would be a second authority with no consumer.

## Further Notes
The install failure that prompted this was reported against
`curl -fsSL .../install.sh | sudo bash` on a host without the Astral toolchain. The exact root
cause was never captured — `curl` was demonstrably present, so the bootstrap's missing `curl`
guard is not the whole story. The builder-selection design removes the dependency on reaching
`astral.sh` regardless, and the new failure message makes the next such report legible. Slice 03
should still try to reproduce the original failure in a clean container.

## Slices
See `01`…`10` in this directory. Four tracks, independent after their prefactors:
install (`01`, `02`, `03`), filter (`04`, `05`, `06`), findings (`04`, `07`, `08`, `09`), and
CSV (`10`). `01` and `04` can both start immediately.
