# Four client cases

*All four are for Harbor Watch MSSP, a fictional client (see the [brief](brief.md)). Numbers come from `evals/results.json`.
`n_malicious = 1`, so every result below is about triage behaviour on mostly benign and undecidable alerts.*

## Case 1: Triage on the night shift
- **Situation.** One analyst, hundreds of endpoint alerts, most of them ordinary admin work that looks like an attack.
- **Discovery questions.** Which alerts do you close in under a minute, and why? What must a verdict contain for you to
  trust it without re-doing the work? What may an agent never touch? What does a wrong close cost versus a needless wake-up call?
- **What was built.** `asa investigate --alert A-007` runs a Claude tool-use loop over five read-only tools and writes a verdict with
  cited event ids, plus a static case page. Planted instruction-shaped text is reported in its own red panel.
- **How it was measured.** Accuracy against an answer key the agent cannot reach, next to a $0 baseline (severity only), and
  cost per alert from the recorded run's token usage at list prices.
- **Result.** 20 of 30 matched (67%) against 15 of 30 (50%) for the baseline. Mean cost $0.048 per alert, maximum $0.102.
  The agent handed 20 of 30 alerts to a person, 10 more than the key expects, and never called an alert malicious.
- **Next step.** Put a price on an unnecessary hand-over and re-measure; add many more malicious examples before claiming anything about detection.

## Case 2: Assurance, "how do I trust a verdict I did not watch?"
- **Situation.** The team lead signs off on shifts they did not work. A fluent, confident write-up is not evidence.
- **Discovery questions.** What would you check first if you had five minutes? Which mistakes are survivable and which are not?
  Would you rather have a checker that misses things or one that cries wolf?
- **What was built.** `asa check <run>`: plain code, no model. It verifies that each cited event exists and was actually returned
  by a tool call, that each quote is a substring of the cited field, that no claim lacks a citation, and that
  instruction-shaped text the agent saw was reported.
- **How it was measured.** On the agent's own 30 runs, and on a regression set: 30 clean runs built from the answer key
  (false flags expected: 0), one mutant per finding kind (all expected to be caught), and four *known misses* that the checker is expected to let through.
- **Result.** 0 unsupported claims in 86 claims across 30 runs. Regression set: 0 of 30 false flags, 6 of 6 mutants caught,
  4 of 4 known misses missed, as designed. A change in either direction fails a test, so this page cannot drift from the code.
- **Next step.** A relevance check (is the cited event about the claim?) and a sampled human review of claims. Zero findings
  means the citations hold up, not that the reasoning is right.

## Case 3: Shift handover
- **Situation.** At 07:00 the night analyst leaves. The day lead needs three lists, fast: what is still open, what changed, and what is waiting on somebody.
- **Discovery questions.** What do you read first at a handover? What got lost last time? Who is allowed to approve what?
- **What was built.** `asa shift-report --since <time>` reads the run folders and writes Markdown with *open* (needs a
  person), *changed* (the verdict differs between runs of one alert) and *waiting* (recommended actions nobody approved).
  `asa approve ACT-001 --as "Night Lead"` records a dry-run approval; nothing is sent.
- **How it was measured.** Tests on fixture run folders for each list. It costs $0 and uses no model. It has not been measured with a team.
- **Result.** On a replay of three alerts it printed three open items, no changes and three waiting actions, in about the
  length of a screen. That shows the format, not the benefit.
- **Next step.** Try it for a week with a real handover and count what the day lead still had to ask.

## Case 4: Proof, "show me afterwards that nobody edited it"
- **Situation.** An auditor asks the team lead, a month later, what the agent looked at on one alert and who approved the action.
- **Discovery questions.** Who may edit the stored runs? What would the auditor accept as proof? Where do logs live that the agent cannot write to?
- **What was built.** A hash-chained `audit.jsonl` per alert, `asa audit verify`, a per-run trust report and a static console to read them. Threat intel runs after triage and is labelled as such.
- **How it was measured.** Tamper tests (one changed byte, a deleted, reordered or duplicated line, a forged first line, a cut-off tail checked against a head hash), and a replay that must give the same head hash on a clean clone.
- **Result.** 30 of 30 replayed trails verify; one changed byte in A-007's `verdict.json` fails at seq 17. The chain is tamper-evident, not tamper-proof: rewriting the whole trail is caught only against a head kept elsewhere.
- **Next step.** Write each head hash to the client's ticket or log store, add signing or outside time-stamping, and name approvers from a login instead of free text.

*A different fictional client (Calder Health MSSP) is in runbook-cards.*
