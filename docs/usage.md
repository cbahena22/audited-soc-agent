# Usage

All commands are read-only and cost $0 unless a section says otherwise. Python 3.11 or newer. On Windows use `.venv\Scripts\` instead of `.venv/bin/`.

## Install
```
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock && .venv/bin/pip install --no-deps -e .
```
The editable install needs `pip` to fetch its build backend once.

## Commands
```
asa demo                                  # the whole flow below for all 30 alerts, then builds out/console/index.html ($0)
asa investigate --alert A-007 --mock      # replay the recorded run: banner, tool calls, verdict, case page under out/
asa investigate --mock --all              # replay all 30 alerts under one run id
asa intel out/runs/<run>/A-007            # post-triage enrichment from synthetic fixtures (no network)
asa trust out/runs/<run>/A-007            # trust report: writes trust.json, prints a 10-line summary
asa audit verify out/runs/<run>/A-007 [--head <sha256> --lines <n>]   # re-hash the trail and the files it points at (exit 1 on a failure)
asa console build                         # static site from out/runs/<run> into out/console (open index.html)
asa check out/runs/<run>/A-007            # evidence checker (exit 0: no findings, 1: findings, 2: bad input)
asa actions out/runs/<run>/A-007          # recommended actions
asa approve ACT-001 --run out/runs/<run>/A-007 --as "Night Lead"   # dry run: recorded, never sent
asa eval checker                          # the checker's regression set: catches, known misses, false flags
asa eval triage --recorded live-20261028  # accuracy vs the answer key and the baseline, cost, effort
asa eval injection                        # planted injections reported
asa shift-report --since 2026-10-01T00:00:00Z   # open / changed / waiting, as Markdown
asa mcp                                   # the same five tools over stdio MCP (JSON-RPC 2.0)
```
`live-20261028` is the id of the one recorded live run (recorded 2026-10-28, evening US Pacific; the files stamp it in UTC, 2026-10-29). `A-007` is the one malicious alert in the data set.

## Live mode (the only thing that costs money)
```
asa investigate --alert A-007 --live --budget 1.00
```
Needs `ANTHROPIC_API_KEY` in the environment and a hard `--budget` (US dollars). Nothing is sent in mock mode.

## Tests
```
.venv/bin/pip install --require-hashes -r requirements-dev.lock && .venv/bin/python -m pytest -q
```

## Data
- `data/` holds 30 synthetic alerts and about 3,500 events over 3 days. `python tools/make_dataset.py --seed 7` rebuilds the generated part byte for byte.
- **n_malicious = 1.** The malicious alert (A-007) is hand-made and abstracted: an alert card, one trigger event and a few neutral context events, with the command line withheld. The other 29 are benign look-alikes (19) and decoys that need a person (10).
- 6 events carry planted text addressed to an AI reviewer. The agent should report it and never follow it.
- The expected result for each alert is in `evals/answer_key.json`, outside `data/`, so no tool can reach it.

## The trail, the trust report and the checklist
- `audit.jsonl` (per alert, in the run folder): one line per step with the hash of the previous line. `asa audit verify` re-hashes it and the files it points at.
  Without `--head` and `--lines` it proves the chain is consistent; with them (the demo run's A-007 values are in the [README](../README.md)) it also catches a cut-off or rewritten tail.
- `trust.json`: what the agent read, what the checker found, injections reported, who approved, cost, the trail's head, and a fixed list of limits.
- `checklist/checklist.json`: the buyer's checklist. `python tools/render_checklist.py` rewrites the README table from it; `--check` exits 1 when they differ.
- Tests: `python -m pytest -q` also checks that every file, function and test the checklist names exists and that the README table matches.

## Security
Read-only tools over `data/` only, stdio-only MCP, a hard spend cap, an inert case page, a key read from the environment. Details and how to report a problem: [SECURITY.md](../SECURITY.md).
