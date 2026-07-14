# Slice 7 — Leak findings: rate what each event discloses

Labels: ready-for-agent

## Parent
`00-PRD-operator-ergonomics.md` — Make the record usable.

## What to build
netmon records disclosures and expects the reader to already know which of them matter. Give it a
**deterministic, stateless assessment** of what each event discloses — and nothing more than that.

The governing invariant: **a rule may only claim what the event's own fields prove.** That single
sentence bans every IDS shape (baselines, novelty, beaconing, rare ports — none of which netmon
has, and none of which it is growing) *and* bans over-claiming, which is the subtler failure. It
also makes each rule trivially testable at the existing packet seam.

Build a fourth projection beside direction / host / detail: a function from one event to at most
one finding. Exactly one, never a list — a graded severity says *how much this cost you*, the rule
id says *what class of disclosure*, and one-per-event makes double-counting structurally impossible
rather than merely discouraged.

A finding carries an aggregation **subject** and a three-part **diagnosis**: what leaked, to whom,
and what the operator can do about it. Structured, not a prose blob — the panel shows the subject,
the detail view renders the diagnosis. Severity is low / medium / high with defined meanings: high
means content that authenticates or identifies you crossed in cleartext, or an internal name left
your network; medium means a specific fact about you reached someone outside this host; low means a
disclosure-*capable* channel was observed but the packet does not prove content left. Note that a
string enum compares **lexically** — `"high" < "low"` — so every severity comparison must go through
an explicit rank map. A bare `>=` is a silent bug.

The rules are in the PRD's table. The **false-positive killers are the design**, not a refinement of
it: loopback is never a leak (the repo's own fixture is a `127.0.0.1` Syncthing REST call — flagging
it would destroy trust in the panel on day one); an ECS record advertising a zero-length prefix is a
leak *prevented*, and flagging it would invert the truth; and findings aggregate by `(rule, subject)`
with a count, so plaintext DNS to one resolver is a single line reading `×1,432`. The mail rules must
not over-claim: netmon never reads the payload and cannot know whether the client upgraded with
STARTTLS, and the diagnosis has to say so — which is *why* they are medium and not high.

**Findings are never written per-event.** The JSONL stays raw evidence; findings stay recomputable
interpretation. The rollup goes into `summary.json`, which is already where derived interpretation
lives. The payoff is large and worth stating plainly: improving a rule re-assesses every historical
run for free, including runs recorded before this feature existed, because the record already
reparses into typed events. No schema change, no migration, and no drift is *possible* — there is one
authority and nothing for it to fall out of step with.

Integration is one hook in the single existing walk over emitted events, so findings are tallied
identically under the dashboard, headless, replay and the systemd recorder — the recorder being the
one that has no dashboard at all, and so depends entirely on the summary. The capture loop, the
writers, the file map and the dashboard model are untouched. The findings table is bounded like every
other table here, and its eviction counter belongs in the coverage ledger: a clean log is not a silent
gap.

Ship two counters alongside — cleartext SNI versus ECH — giving an honest ECH-coverage figure for the
run. That is the useful form of a fact that would be worthless as a rule, since a cleartext-SNI rule
would fire on nearly every flow.

## Acceptance criteria
- [ ] A cleartext HTTP POST to an internet host yields a high-severity finding naming the host, what leaked, and what to do; the same request to loopback yields **none**.
- [ ] A DNS query to a public resolver is a medium finding whose subject is the **resolver**, not the queried name, so one busy resolver is one row with a count.
- [ ] A query for an internal-shaped name sent to a public resolver is high severity.
- [ ] An LLMNR/NBNS broadcast is a finding; one for `wpad` is high severity.
- [ ] An ECS record with a non-zero prefix is a finding; one advertising a zero-length prefix is **not**.
- [ ] A flow to a plaintext credential-capable service is a finding whose advice states netmon cannot see whether STARTTLS was used.
- [ ] `summary.json` carries a findings rollup — counts by severity, by rule, and the top subjects with counts — under headless, replay and TUI runs alike.
- [ ] `summary.json` carries cleartext-SNI and ECH counters, so ECH coverage is readable without a rule that cries wolf.
- [ ] The findings table is bounded, and overflow is counted in the coverage ledger rather than dropped silently.
- [ ] Every rule is reachable from the assessor, the severity rank covers every severity, and the service-leak table is a subset of the known services — all asserted, in the idiom the repo already uses for the per-kind style map.
- [ ] The assessor dispatches on the kind discriminator, proven by the module-copy test.
- [ ] The event schema, the file map, the writers and the capture loop are unchanged.

## Blocked by
- `04-total-event-projections.md` — the rules classify the peer with `event_scope`.
