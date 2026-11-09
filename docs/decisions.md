# Decisions

Short records of the choices that shaped this repo. Each says what was chosen, why, and what it costs.

## 1. A manual tool-use loop on the plain SDK
- **Decision:** `src/asa/agent.py` runs the loop itself (call, run the tools, call again) on the official `anthropic` SDK. No agent framework.
- **Why:** the loop owns every turn. The spend cap is checked before each request, every turn is recorded for replay, and every
  tool argument passes through the tools' own checks before use.
- **Cost:** about 200 lines of loop code to maintain, including the stop handling (refusal, token limit, no verdict, turn limit).

## 2. One model for all alerts, no server-side fallback
- **Decision:** one model per run (`claude-sonnet-5-5`, effort `high` by default). Automatic fallback to another model is off.
  A price table accepts only known models; anything else is refused.
- **Why:** one result table should describe one thing. A silent fallback would mix two models in one number.
- **Cost:** a refusal or an overloaded API ends that alert with `needs_human`, not a retry on something else.

## 3. A deterministic evidence checker
- **Decision:** `asa check` is plain code. It checks that each cited event exists and was returned by a tool call, that each
  quote is a substring of its event field, that every claim has a citation, and that instruction-shaped text the agent saw was reported.
- **Why:** a checker that is itself a model has the same failure modes as what it checks. Plain code is cheap, repeatable and
  testable.
- **Cost:** it reads citations and quotes, not meaning. `asa eval checker` lists four known misses on purpose (a claim that
  contradicts a correctly quoted event, an irrelevant but real citation, a trivially short quote, a flipped verdict checked without the answer key).

## 4. Dry-run approvals; no executor
- **Decision:** `asa approve ACT-001 --as "Night Lead"` appends "approved (dry run, not sent)" to a file. No module can send or
  execute an action, and a test scans the code to keep it that way.
- **Why:** the pilot proves the review step, not remote control. Adding an executor later is a separate, reviewed change.
- **Cost:** the demo ends one step early on purpose.

## 5. A stdio MCP server without an SDK
- **Decision:** `asa mcp` speaks JSON-RPC 2.0 over stdin and stdout, about 100 lines, and exposes the same five read-only tools.
- **Why:** the protocol surface needed here is small (`initialize`, `ping`, `tools/list`, `tools/call`). Fewer dependencies, a
  smaller attack surface, and a reader can see all of it. Every tool is marked `readOnlyHint`.
- **Cost:** not a full MCP implementation. No resources, prompts or notifications.

## 6. Synthetic, seeded data; few malicious examples, stated plainly
- **Decision:** `data/` is built by `tools/make_dataset.py --seed 7` (30 alerts, about 3,500 events). The malicious alerts are
  hand-made and abstracted (alert-card fields, the command line withheld); the benign look-alikes and decoys around them are generated. `n_malicious = 1`.
- **Why:** no real data, and no working attacker tooling in a public repo. The look-alikes are named neutrally, so a host or file
  name never gives the answer away.
- **Also:** the answer key (`evals/answer_key.json`) sits outside `data/`. Tools open files only under `data/`, and a test tries
  to reach the key through every tool argument.
- **Cost:** results on malicious alerts are indicative only. Every results table says so.

## 7. Replay for $0
- **Decision:** one live run was recorded (every model response and every tool-result hash). `--mock` and every eval replay it
  with no key and no network. A replay must request the same tool calls and get the same result hashes, or it stops with an error.
- **Why:** anyone can reproduce the numbers, and the demo needs no credentials.
- **Cost:** the recording is one run, so there is no variance estimate.

## 8. A static case page with a hash-pinned CSP
- **Decision:** `case.html` escapes all text, keeps no inline `on*=` handlers or `style=` attributes, writes with `textContent`
  only, and its CSP allows exactly the inline script and style by sha256 hash. No external URL.
- **Why:** model output and event text are untrusted. A page that renders them must stay inert even for a title like
  `</script><img src=x onerror=...>` (a test covers it).
- **Cost:** the page is plain. Citations are `<details>` elements, not an interactive viewer.

## 9. No CI on this repo
- **Decision:** tests run locally, in a hash-locked environment. There are no workflow files.
- **Why:** no secrets or spend can ever be reachable from a hosted runner. One runtime dependency, universal hash locks.
- **Cost:** no badge. Run `python -m pytest -q`.

## 10. A hash chain for the audit trail, not signatures
- **Decision:** each alert gets `audit.jsonl`, one JSON line per step. A line holds the SHA-256 of the line before and of the record it
  describes (`transcript.jsonl`, `verdict.json`, `check.json`, `approvals.jsonl`, `intel.json`). `asa audit verify` re-hashes the lines and those files.
  Appends run under a lock and refuse when the existing chain does not verify. No signing keys, no outside time-stamping.
- **Why:** a buyer needs to see an edit, and a chain shows one with the standard library alone: no key to store, lose or leak, nothing to install.
  The trail holds hashes and short summaries, not copies of the transcript, so it adds no second copy of event text.
- **Cost:** tamper-evident, not tamper-proof. Whoever can rewrite the whole trail can rewrite its hashes, and cutting lines off the end is
  caught only against a head hash and line count kept elsewhere. The README pins the head of the demo run (21 lines for A-007); a real
  deployment would write the head to a ticket or log store. Signatures and time-stamping are the next step.

## 11. A static console, not a server
- **Decision:** `asa console build` writes plain HTML files from the run folders: queue, case, trust report, audit trail, checklist,
  about. No server, no script, no outside request; one CSP per page (`default-src 'none'`, inline style by hash, images inline).
  All data is escaped as untrusted, JSON is embedded safely, and the build is deterministic (same inputs, same bytes).
- **Why:** the page shows model output and event text that were written to manipulate an AI reader, so it must stay inert, and a
  folder of files has nothing to log in to, patch or attack. A reviewer opens it from disk.
- **Cost:** it replays; it cannot run the agent or take an approval. Approvals stay in the command line, and the console shows the recorded ones.
  The chain banner says "verified when this page was built", not "verified now".

## 12. Threat intel after triage, in plain code
- **Decision:** `asa intel` runs after the verdict. It takes indicators only from typed fields (addresses, DNS names, hashes) of events
  the verdict cites and the agent was shown, skips fields named in an injection report and the client's own domains, looks them up
  and marks each `contain`, `review` or `clear` by a fixed decision table. The agent has no lookup tool and the verdict never uses the result.
- **Why:** text in a log is written by whoever caused the event. Turning free text into a lookup or a verdict would give that person
  a lever, and an extra paid model run would not change what the buyer needs to see. A table is readable and testable.
- **Cost:** the agent cannot use intel to reach a better verdict, and enrichment adds nothing to accuracy. It adds context for the person who reads the case.

## 13. Fixtures, not real lookups
- **Decision:** provider answers come from synthetic fixtures shaped like VirusTotal, AbuseIPDB and OTX responses. The package has no network
  code, no API-key handling and no environment reads in the intel step, and a test enforces it. Every view labels the result
  "post-triage enrichment (synthetic provider answers)".
- **Why:** a public demo that calls third-party services needs keys and rate limits, can leak what it looks up, and the VirusTotal
  public API terms are non-commercial. Fixtures make the demo repeatable, free and safe to run offline.
- **Cost:** nothing here says anything about a real address or file. Real lookups would need each provider's terms, caching, rate limits and a review of what leaves the network.

