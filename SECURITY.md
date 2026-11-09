# Security

## Reporting a vulnerability
Please use GitHub's private vulnerability reporting: the **Security** tab of this repository, then **Report a vulnerability**.
Do not open a public issue for a security problem. Expect an acknowledgement within a few days; this is a portfolio project
maintained by one person, so there is no service-level promise.

Useful reports: a way to make the agent follow instruction-shaped text in an event, a path or id that escapes `data/`, output
that is not inert in the case page or the console, a way to exceed `--budget`, a way to send an action, a change to a stored run that
`asa audit verify` still passes, or a way for the threat-intel step to turn event text into a lookup.

## What leaves your machine
- **Mock mode and every eval** (the default way to run this repo): nothing. No client object is created and no socket is opened (a test patches sockets to raise).
- **Live mode** (`--live --budget <usd>`, needs `ANTHROPIC_API_KEY`): requests to `https://api.anthropic.com` containing the
  system prompt, the tool definitions, the synthetic alert and the synthetic tool results. Nothing else. No client data exists
  in this repo.
- The official SDK adds its usual platform headers to each request (SDK version, operating system, CPU architecture, Python version).
- No telemetry, analytics, tracker or update check is part of this code.

## What is stored
- `out/` (git-ignored): run folders (transcript, verdict, case page, check result, approvals) and the spend ledger. Paths are repo-relative.
- `evals/recorded/`: model responses from the one recorded run, with thinking signatures removed. No request headers, no key, no request ids.
- The key is read from the environment only, never logged, printed or recorded. The code refuses to start live mode when
  `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL` or `ANTHROPIC_PROFILE` is set, so a request cannot be redirected to another endpoint or credential.

## Built-in protections
- Tools are read-only and open files only under `data/`; every id and argument is checked in code. The MCP server is stdio only, with no network listener.
- Event text is treated as data. The agent reports instruction-shaped text in its own field, and the checker flags any that went unreported.
- Approvals are dry runs. No module can send or execute an action (a code scan enforces it).
- The case page escapes all text, escapes inline JSON (including U+2028 and U+2029), uses `textContent` only, and carries a CSP that pins its one inline script and style by hash.
- Spend: a reserve is booked before every request, an append-only ledger survives a crash, an unknown model is refused, and `--live` without `--budget` is refused.
- Dependencies: one runtime dependency, installed from hash-locked files (`pip install --require-hashes`).

## The audit trail (threat notes)
- **What it protects:** the record of one alert: `audit.jsonl` links each step to the one before by SHA-256 and names the hash of the
  transcript, verdict, check result, approvals and intel files. `asa audit verify` re-hashes all of it.
- **What it detects:** an edited or removed line, a reordered or duplicated line, a forged first line, an edited stored file, an
  approval written outside the tool, and (against a head hash and line count kept elsewhere) a cut-off or fully rewritten trail.
- **What it does not stop:** tamper-evident, not tamper-proof. Someone who can write the run folder can rewrite the whole chain with valid
  hashes; without an outside head hash nothing shows it. There are no signing keys and no outside time-stamps. Approver names are free text.
- **Writers:** appends take an exclusive lock file (a token inside it; a stale lock is taken over only under a second guard file) and refuse when the
  existing chain does not verify. A crash that leaves a guard file behind is cleared after 30 seconds without a further check: a residual limit.
  Known limits: a guard file that cannot be removed (for example a Windows sharing violation from a virus scanner) is left to go stale, so writers wait or refuse; and the stale-guard removal can race with a new guard being created, so in a rare interleaving two writers could overlap; that shows up as a chain that fails `asa audit verify`, it is not hidden.
- **Reads:** every file the trail, trust report and console read comes from `out/` or `data/`, is size-capped (32 MB) and checked against its schema;
  a linked trail file is refused.

## The console (threat notes)
- **Static pages only:** no server, no login, no script, no outside request. Each page carries a CSP with `default-src 'none'`, inline style
  allowed by hash only, images inline. A test builds the site from planted event text (`</script>`, markup, handler attributes) and checks it renders as text.
- **Untrusted data:** event text, model claims, provider fields and trail summaries are escaped everywhere. Code links use one configured base URL and no
  other absolute link is allowed.
- **What the banner means:** "chain verified when this page was built" is a statement about build time. Run `asa audit verify` for now.
- **Threat-intel step:** it reads typed fields of cited events only (never free text), skips fields named in an injection report, makes no network call and
  reads no key or environment variable (a test enforces both). Its answers are synthetic fixtures and the verdict never uses them.

## Scope
Synthetic data only. This is a read-only pilot, not a product: there is no login, no server and no tenant model. Run folders are trusted to the extent of the audit trail above, no further.
