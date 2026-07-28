# netmon domain glossary

One concept, one word — the same terms in conversation, code, and record. A term
earns a row here when a module is named after it or a vocabulary is closed
around it.

| Term | Meaning |
|---|---|
| **kind** | The stable string discriminator every `Event` carries (`dns_query`, `tls_sni`, `flow`, …). Dispatch is always on `.kind`, never `isinstance`. |
| **scope** | Reachability class of the *peer*: `internet`, `cgnat`, `lan`, `linklocal`, `loopback`, `multicast`. |
| **direction** | `outbound` / `inbound` / `local` / `transit` — whose disclosure a packet is. |
| **from_self** | Did THIS host send it, or did we merely overhear it? Recorded on the event because the record is the evidence. |
| **fate** | The one ledger entry every captured packet gets, exactly once (`event`, `no_disclosure`, `parse_error`, …). The coverage ledger's honesty guarantee. |
| **finding / rule / severity** | What an event *discloses*, rated. A rule may only claim what the event's own fields prove. Never persisted — recomputed. |
| **projection** | A *total* derived function over `Event` (`event_host`, `assess`, …). Total is the point. |
| **run directory** | A recorded run on disk: per-kind JSONL, rotation archives, `summary.json`. The read side (resolve the run the operator meant, validate, read archives back as one record) is owned by the `RunDirectory` module — `audit` and `query` consume runs only through it. |
| **one authority per fact** | The house rule: each piece of knowledge lives in exactly one place; everything else derives or is pinned to it by a test. |
