# Brief: Harbor Watch MSSP

*A fictional client. Every name, host, address and number in this repo is made up.*

## Who
Harbor Watch is a managed security provider with 5 analysts watching endpoint alerts for 30 small clients (clinics, law
offices, a few light-industry firms). Nights are the problem: one analyst, hundreds of alerts, most of them ordinary admin work
that happens to look like an attack.

## The ask
> "Can an agent do the first pass on an alert, and how do I trust a verdict I did not watch?"
> (the team lead)

The second half is the harder one. Trust here means the lead can ask five things and get an answer from a file, not from the
agent: what did it look at, can planted text steer it, who approved what, what did it cost, and was the record edited afterwards.
The [buyer's checklist](../README.md#the-buyers-checklist) turns those into twelve questions, each tied to code and a test.

## Constraints
- **Read-only.** The agent may look at a client's events. It may not change anything on a client's systems.
- **Nothing changes without a person.** Any response action (isolate a host, disable an account, block an address) is a
  suggestion that a named person approves.
- **A cost per alert.** The team lead wants a number, not "it depends", and a hard cap on spend.
- **Explainable.** Each claim in a verdict points at the event it rests on, so a tired analyst can check it in seconds.
- **Provable afterwards.** Every step an alert took is kept in an append-only trail where each line holds the hash of the one
  before. The lead can re-check it later and see an edit. It is tamper-evident, not tamper-proof (the README says how to anchor it).
- **Untrusted text.** Command lines, file names and DNS names are written by whoever caused the event. Some will be written
  to talk to an AI reader. The agent must report that text, not obey it.

## Success measures
| Measure | Target for the pilot | Where it is measured |
|---|---|---|
| Right first-pass call against a known answer, compared with a plain severity rule | better than the severity-only baseline | `asa eval triage` |
| Claims with no support in the cited events | none the checker can find | `asa check`, `asa eval triage` |
| Planted instruction-shaped text reported, not followed | every one | `asa eval injection` |
| Cost per alert | a stated mean and maximum, under a hard budget | `asa eval triage` |
| Actions executed without a person | zero (no executor exists) | tests |
| Record edited after the run | an edit to any stored file fails `asa audit verify` at the line it touches | `asa audit verify`, `tests/test_audit.py` |
| A claim a buyer cannot trace | none: each trust claim has a console view, code and a test | `tests/test_checklist.py` |

## Out of scope for the pilot
A real SIEM connector, real client data, executing any action, more than one model, signing keys or outside time-stamping for the
trail, real threat-intel lookups (the enrichment step uses synthetic provider answers), and a claim that this generalises beyond
the 30 synthetic alerts. See "Honest limits" in the [README](../README.md).

Results: [pilot readout](pilot-readout.md). What was built for each ask: [cases](cases.md).
