"""The static console: every page parses, carries one hash-matched CSP and no script, renders untrusted text inert,
links only to its own pages or the code base, builds byte-for-byte the same twice, and passes the publish shapes."""
import ast
import json
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from asa.case_page import csp_hash
from asa.console import pages
from asa.console.build import build, check_trail, render_site
from asa.console.load import load_alert
from console_fixtures import CODE_BASE, HOSTILE, RUN_ID, add_trust_files, fake_verify, full_run, write_jsonl
import console_gate

PAGE_HREF = re.compile(r"^(index|about|checklist|(case|trust|audit)-A-\d{3})\.html(#[A-Za-z][A-Za-z0-9-]*)?$|^#[A-Za-z0-9-]+$")
VOID = {"meta", "br", "hr", "img", "input", "link", "col", "area", "base", "wbr", "source"}


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    """All 30 alerts replayed, checked, two scripted approvals, hand-written trust files; the A-007 event and
    summaries carry hostile text. Built once with the test verifier."""
    tmp = tmp_path_factory.mktemp("console")
    repo, runs_dir = full_run(tmp)
    # Hostile text in every untrusted source the pages render: an event field, the verdict, the trail, intel, checklist.
    events = repo.base / "data" / "events.ndjson"
    lines = events.read_text(encoding="utf-8").splitlines()
    for i, raw in enumerate(lines):
        ev = json.loads(raw)
        if ev["event_id"] == "E-000103":
            ev.setdefault("process", {})["name"] = "powershell.exe " + HOSTILE
            lines[i] = json.dumps(ev)
    events.write_text("\n".join(lines) + "\n", encoding="utf-8")
    a12 = runs_dir / "A-012"
    v = json.loads((a12 / "verdict.json").read_text(encoding="utf-8"))
    v["summary"] = HOSTILE
    (a12 / "verdict.json").write_text(json.dumps(v), encoding="utf-8")
    trail = [json.loads(x) for x in (a12 / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    from console_fixtures import chain
    write_jsonl(a12 / "audit.jsonl", chain([(t["kind"], t["actor"], HOSTILE if t["seq"] == 2 else t["summary"], {}) for t in trail]))
    intel = json.loads((a12 / "intel.json").read_text(encoding="utf-8"))
    intel["indicators"][0]["value"] = HOSTILE
    intel["indicators"][0]["providers"]["vt"]["fields"]["note"] = HOSTILE
    (a12 / "intel.json").write_text(json.dumps(intel), encoding="utf-8")
    out = repo.path("out", "console", write=True)
    result = build(repo, runs_dir, out, code_base=CODE_BASE, verify=fake_verify)
    pages_ = {p.name: p.read_text(encoding="utf-8") for p in sorted(out.iterdir()) if p.suffix == ".html"}
    return {"repo": repo, "runs": runs_dir, "out": out, "result": result, "pages": pages_, "tmp": tmp}


class Strict(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.errors, self.attrs = [], [], []

    def handle_starttag(self, tag, attrs):
        self.attrs.append((tag, attrs))
        if tag not in VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}> (open: {self.stack[-3:]})")
            return
        self.stack.pop()


def parse(html: str) -> Strict:
    p = Strict()
    p.feed(html)
    p.close()
    return p


def test_site_has_every_page(site):
    names = set(site["pages"])
    assert {"index.html", "checklist.html", "about.html"} <= names
    for n in range(1, 31):
        for kind in ("case", "trust", "audit"):
            assert f"{kind}-A-{n:03d}.html" in names
    assert site["result"]["pages"] == 93 and site["result"]["alerts"] == 30
    assert site["result"]["trails"]["verified"] and not site["result"]["trails"]["failed"]
    manifest = json.loads((site["out"] / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["generator"] == "asa console build" and manifest["run"] == RUN_ID and len(manifest["files"]) == 93


def test_every_page_parses_balanced(site):
    for name, html in site["pages"].items():
        p = parse(html)
        assert not p.errors, (name, p.errors[:3])
        assert not p.stack, (name, p.stack)
        assert html.startswith("<!doctype html>\n") and html.count("<main>") == 1


def test_one_csp_per_page_hash_matched_and_no_script(site):
    for name, html in site["pages"].items():
        metas = re.findall(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html)
        assert len(metas) == 1, name
        csp = metas[0]
        styles = re.findall(r"<style>(.*?)</style>", html, re.S)
        assert len(styles) == 1, name
        assert f"style-src '{csp_hash(styles[0])}'" in csp
        for part in ("default-src 'none'", "script-src 'none'", "img-src 'self' data:", "base-uri 'none'", "form-action 'none'"):
            assert part in csp, (name, part)
        assert "<script" not in html.lower(), name


def test_untrusted_text_renders_as_text(site):
    for name, html in site["pages"].items():
        for tag, attrs in parse(html).attrs:
            assert tag not in ("script", "img", "iframe", "object", "embed", "form"), (name, tag)
            for key, _ in attrs:
                assert not key.startswith("on") and key != "style", (name, tag, key)
        assert "innerHTML" not in html
    escaped = "&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;img src=x onerror=alert(2)&gt;"
    assert escaped in site["pages"]["case-A-007.html"]  # the event field (E-000103), opened from a citation
    case12, audit12 = site["pages"]["case-A-012.html"], site["pages"]["audit-A-012.html"]
    assert escaped in case12  # verdict summary and intel value / provider field
    assert case12.count(escaped) >= 3
    assert escaped in audit12  # trail summary
    assert escaped in site["pages"]["checklist.html"]


def test_links_are_own_pages_or_the_code_base(site):
    names = set(site["pages"])
    for name, html in site["pages"].items():
        for tag, attrs in parse(html).attrs:
            for key, value in attrs:
                if key in ("src", "action", "srcset", "poster", "data"):
                    raise AssertionError((name, tag, key))
                if key != "href":
                    continue
                if value.startswith(CODE_BASE):
                    rest = value[len(CODE_BASE):]
                    assert re.fullmatch(r"(src|tests|tools|evals|data|checklist|docs)/[A-Za-z0-9_./-]+", rest) and ".." not in rest
                    continue
                assert PAGE_HREF.fullmatch(value), (name, value)
                target = value.split("#")[0]
                assert not target or target in names, (name, value)
        no_base = html.replace(CODE_BASE, "").replace("<code>https://evil.example/x</code>", "")  # the hostile row, as text
        assert "http://" not in no_base and "https://" not in no_base, name


def test_build_is_deterministic(site):
    out2 = site["repo"].path("out", "console2", write=True)
    build(site["repo"], site["runs"], out2, code_base=CODE_BASE, verify=fake_verify)
    first = sorted(p.name for p in site["out"].iterdir())
    assert first == sorted(p.name for p in out2.iterdir())
    for name in first:
        assert (site["out"] / name).read_bytes() == (out2 / name).read_bytes(), name


def test_no_absolute_path_or_publish_shape_in_the_site(site):
    needles = {str(site["tmp"]), site["tmp"].as_posix(), str(site["repo"].base)}
    for p in sorted(site["out"].iterdir()):
        text = p.read_text(encoding="utf-8")
        for needle in needles:
            assert needle not in text, p.name
        assert console_gate.hits(text) == [], (p.name, console_gate.hits(text)[:5])


def test_style_hash_has_no_publish_shape():
    # The CSP hash is random-looking base64: a style change can create a shape by chance. Change the style text if so.
    assert console_gate.hits(pages.csp()) == []


def test_queue_page(site):
    q = site["pages"]["index.html"]
    assert q.count('<a href="case-A-') == 30
    assert "20/30 verdicts match the answer key; a severity-only rule gets 15/30." in q
    assert "It hands 20 of 30 alerts to a person; the answer key expects 10 (it over-escalates)." in q
    assert "1 malicious alert in the set; the agent marked 0 as malicious." in q
    assert "self-declared" in q
    assert 'data-label="Injection"><span class="bad">1 reported</span>' in q
    assert "review 1 / clear 1" in q
    assert "Synthetic data." in q and "live-20261028" in q and "$0, no model call" in q
    assert "recorded 2026-10-28)" in q and "2026-10-29" not in q  # the date in the recording id, not the UTC stamp
    # 7 reports, but A-008 reported its one planted text twice (file.name and file.path): no report outside the planted set
    assert ("7 injection reports by the agent on 6 alerts (A-008: 2 reports on 1 event, one per field); "
            "6 of 6 planted instruction-shaped texts reported (evals/results.json).") in q


def test_injection_summary_counts_alerts_repeats_and_planted(tmp_path):
    from asa.console.load import AlertRun

    def run(alert_id, *reports):
        return AlertRun(alert_id=alert_id, run_dir=tmp_path, verdict={"injection_reports": list(reports)})

    runs = [run("A-001", {"event_id": "E-000001", "field": "a"}),
            run("A-002", {"event_id": "E-000002", "field": "a"}, {"event_id": "E-000002", "field": "a"}),
            run("A-003", {"event_id": "<b>x</b>", "field": "a"}, {"event_id": "E-000003", "field": "b"}), run("A-004")]
    site = pages.Site(run_id=RUN_ID, recording="live-20261028", planted=(2, 3))
    assert pages.injection_summary(runs, site) == (
        "5 injection reports by the agent on 3 alerts (A-002: 2 reports on 1 event); "
        "2 of 3 planted instruction-shaped texts reported (evals/results.json)")
    assert pages.injection_summary([run("A-004")], pages.Site(run_id=RUN_ID)) == "0 injection reports by the agent"
    # results.json for another recording, or without numbers, adds no planted count
    inj = {"recording": "live-20261028", "reported": 6, "n": 6}
    assert pages.planted_counts({"injection": inj}, "live-20261028") == (6, 6)
    assert pages.planted_counts({"injection": inj}, "live-20261030") is None
    assert pages.planted_counts({"injection": dict(inj, n="6")}, "live-20261028") is None
    assert pages.planted_counts(None, "live-20261028") is None


def test_case_page_panels(site):
    c = site["pages"]["case-A-007.html"]
    for anchor in ('id="injection"', 'id="claims"', 'id="checker"', 'id="intel"', 'id="actions"'):
        assert anchor in c
    assert "Reported and escalated to a person." in c
    assert "reasoned past" not in c.lower()
    assert pages.INTEL_LABEL in c and "The verdict did not use this step" in c
    assert "approved as a dry run by scripted demo approval" in c and "self-declared" in c
    assert "0 findings on 3 claims" in c
    assert c.count("<details>") >= 4
    assert '<nav class="sub" aria-label="this alert">' in c and 'href="trust-A-007.html"' in c


def test_trust_page_rows(site):
    t = site["pages"]["trust-A-007.html"]
    assert '<span class="mark pass">pass</span>It changed nothing in your environment' in t
    assert "Actions recommended: 1; approved as dry runs: 1; executed: 0." in t
    assert "Reported and escalated 1 (E-000102); 0 followed." in t
    assert '<span class="mark pass">pass</span>The record was not edited' in t and "chain verified, head " in t
    assert pages.INTEL_LABEL in t and "20/30 verdicts" in t
    assert "ACT-001 by scripted demo approval" in t
    assert 'id="limits"' in t
    other = site["pages"]["trust-A-009.html"]
    assert "No instruction-shaped text reported" not in other or "0 followed" in other
    assert "not computed for this alert" in other  # followed = null in the fixture when nothing was reported


def test_audit_page_banner_and_rows(site):
    a = site["pages"]["audit-A-007.html"]
    head = json.loads((site["runs"] / "A-007" / "trust.json").read_text(encoding="utf-8"))["audit"]["head_sha256"]
    assert f"Chain verified when this page was built, head <span class=\"hash\">{head}</span>" in a
    assert f"asa audit verify out/runs/{RUN_ID}/A-007" in a
    assert a.count("<tr>") >= 9 and "person:scripted demo approval" in a


def test_case_page_carries_the_trail_banner(site):
    """The README hero is the A-007 case page: it shows the same build-time chain banner as the audit page."""
    c = site["pages"]["case-A-007.html"]
    head = json.loads((site["runs"] / "A-007" / "trust.json").read_text(encoding="utf-8"))["audit"]["head_sha256"]
    assert f"Chain verified when this page was built, head <span class=\"hash\">{head}</span>" in c
    assert f"re-run <code>asa audit verify out/runs/{RUN_ID}/A-007</code>" in c
    assert c.index("Chain verified") < c.index('id="injection"')  # in frame with the injection panel, above it


def test_tampered_trail_shows_failed(site, tmp_path):
    run = load_alert(site["runs"] / "A-007")
    lines = (site["runs"] / "A-007" / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    copy = tmp_path / "A-007"
    copy.mkdir()
    for f in (site["runs"] / "A-007").iterdir():
        (copy / f.name).write_bytes(f.read_bytes())
    lines[3] = lines[3].replace("12 events", "13 events")
    (copy / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    run = load_alert(copy)
    trail = check_trail(run, fake_verify)
    assert trail["state"] == "failed" and trail["first_bad_seq"] == 4
    site_ = pages.Site(run_id=RUN_ID)
    html = pages.audit_page(site_, run, {}, trail)
    assert "Chain did NOT verify when this page was built: first bad line 4" in html
    from types import SimpleNamespace
    case = pages.case_console_page(site_, run, {}, SimpleNamespace(by_id={}), trail)
    assert "Chain did NOT verify when this page was built: first bad line 4" in case
    assert '<span class="mark fail">fail</span>The record was not edited' in pages.trust_page(site_, run, {}, trail)


def test_trail_not_checked_without_verifier_or_file(site, tmp_path):
    run = load_alert(site["runs"] / "A-003")
    assert check_trail(run, None)["state"] == "not_checked"
    assert "audit module is not installed" in check_trail(run, None)["reason"]

    def boom(_):
        raise RuntimeError("x")

    assert check_trail(run, boom) == {"state": "not_checked", "head": run.trail[-1]["sha256"], "first_bad_seq": None,
                                      "reason": "verify raised RuntimeError"}
    assert check_trail(run, lambda _: (False, 2, "bad link"))["state"] == "failed"
    assert check_trail(run, lambda _: True)["state"] == "verified"
    run.trail = None
    assert check_trail(run, fake_verify)["reason"] == "no audit.jsonl in the run folder"


def test_checklist_page(site):
    c = site["pages"]["checklist.html"]
    assert '<a href="trust-A-007.html#rows">trust:A-007#rows</a>' in c
    assert '<a href="case-A-007.html#injection">' in c and '<a href="audit-A-007.html#chain">' in c
    assert f'<a href="{CODE_BASE}src/asa/tools.py"><code>src/asa/tools.py::Dataset</code></a>' in c
    assert f'<a href="{CODE_BASE}tests/test_audit.py"><code>tests/test_audit.py::test_tamper</code></a>' in c
    assert '<span class="tag">being built</span>' in c and '<div class="card row" id="Q01">' in c
    s = pages.Site(run_id=RUN_ID, alert_ids={"A-007"})
    assert pages.view_href("checklist#Q03", s) == ("checklist.html#Q03", "checklist#Q03")
    assert pages.view_href("about#limits", s) == ("about.html#limits", "about#limits")
    for bad in ("about:A-007", "case", "case:A-008", "trust:A-007#a b", "case:A-007#x\"y", None, 7):
        assert pages.view_href(bad, s) is None, bad
    # A view naming an alert that is not in the run, a path leaving the repo and foreign URLs stay plain text.
    assert "<code>case:A-999</code>" in c and "<code>../etc/passwd::x</code>" in c
    assert "<code>https://evil.example/x</code>" in c and 'href="https://evil' not in c and 'href="javascript' not in c


REAL_CHECKLIST = Path(pages.__file__).resolve().parents[3] / "checklist" / "checklist.json"


@pytest.mark.skipif(not REAL_CHECKLIST.is_file(), reason="checklist/checklist.json not in this version yet")
def test_real_checklist_rows_link_to_built_views():
    rows = json.loads(REAL_CHECKLIST.read_text(encoding="utf-8"))
    rows = rows["rows"] if isinstance(rows, dict) else rows
    s = pages.Site(run_id=RUN_ID, alert_ids={f"A-{n:03d}" for n in range(1, 31)})
    for row in rows:
        if row.get("pending"):
            continue
        assert pages.view_href(row.get("console_view"), s), (row.get("id"), row.get("console_view"))
        for item in list(row.get("code") or []) + list(row.get("tests") or []):
            assert 'href="' in pages.code_link(item, s), (row.get("id"), item)


def test_checklist_missing_or_broken(site, tmp_path):
    s = pages.Site(run_id=RUN_ID)
    assert "checklist/checklist.json not found" in pages.checklist_page(s, None, None)
    assert "could not be read: not valid JSON" in pages.checklist_page(s, None, "not valid JSON (JSONDecodeError)")


def test_about_page(site):
    a = site["pages"]["about.html"]
    for text in ("Harbor Watch MSSP is a fictional", "replay of recorded run live-20261028", "costs $0",
                 "The replay writes the audit trail; a live run writes it as it goes.", "scripted demo approval",
                 "asa demo", "asa audit verify", "tamper-evident, not tamper-proof", pages.INTEL_LABEL,
                 "recorded 2026-10-28)", "the recorded date is the one in the recording id", "are UTC"):
        assert text in a, text


def test_phone_width_rules_present():
    assert "@media (max-width: 640px)" in pages.STYLE and "td::before { content: attr(data-label)" in pages.STYLE
    assert "overflow-wrap: anywhere" in pages.STYLE


def test_code_base_is_checked(site):
    from asa.common import UsageError

    for bad in ("http://github.com/x/audited-soc-agent/blob/main/", "https://evil.example/", "https://github.com/x/other/blob/main/",
                'https://github.com/x/audited-soc-agent/blob/main/"><script>', "https://github.com/x/audited-soc-agent/blob/main"):
        with pytest.raises(UsageError):
            render_site(site["repo"], site["runs"], code_base=bad, verify=None)


def test_console_modules_import_nothing_networked():
    src = Path(pages.__file__).resolve().parents[1]
    banned = ("subprocess", "socket", "urllib", "http", "requests", "httpx", "ssl", "webbrowser", "anthropic")
    for path in sorted((src / "console").glob("*.py")) + [src / "demo.py", src / "case_page.py"]:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                [node.module] if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module else []
            for name in names:
                assert name.split(".")[0] not in banned, (path.name, name)


def test_trust_files_missing_show_notes(tmp_path):
    from console_fixtures import make_repo, replay
    from asa.common import Repo

    repo = Repo(make_repo(tmp_path))
    runs_dir = replay(repo, ["A-007"])
    (runs_dir / "A-007" / "audit.jsonl").unlink()  # a run folder from before audit trails
    files, summary = render_site(repo, runs_dir, verify=None)
    assert summary["trails"]["not_checked"] == ["A-007"]
    assert "No trust report for this alert yet (asa trust out/runs/" in files["trust-A-007.html"]
    assert "No intel step for this alert (asa intel out/runs/" in files["case-A-007.html"]
    assert "No audit.jsonl in out/runs/" in files["audit-A-007.html"]
    assert "The evidence checker has not run on this alert" in files["case-A-007.html"]
    assert "checklist/checklist.json not found" in files["checklist.html"]
    add_trust_files(runs_dir / "A-007", intel=False)
    files, _ = render_site(repo, runs_dir, verify=None)
    assert "Not run for this alert." in files["trust-A-007.html"]


def test_check_trail_uses_the_real_verifier(tmp_path):
    """build.check_trail calls asa.audit.verify(run_dir) -> (ok, first_bad_seq, reason): verified, then FAIL at the right seq."""
    from console_fixtures import make_repo, replay
    from asa import audit
    from asa.common import Repo
    import importlib
    from asa.console import load

    build = importlib.import_module("asa.console.build")  # the module (the package re-exports the function `build`)

    assert build.default_verify() is audit.verify
    repo = Repo(make_repo(tmp_path))
    runs_dir = replay(repo, ["A-007"])
    run, = load.load_run(runs_dir)[0]
    assert build.check_trail(run, build.default_verify())["state"] == "verified"
    verdict = runs_dir / "A-007" / "verdict.json"
    edited = json.loads(verdict.read_text(encoding="utf-8"))
    edited["confidence"] = "low" if edited["confidence"] != "low" else "high"
    verdict.write_text(json.dumps(edited), encoding="utf-8")
    ok, bad, why = audit.verify(runs_dir / "A-007")
    run, = load.load_run(runs_dir)[0]
    trail = build.check_trail(run, build.default_verify())
    assert not ok and trail["state"] == "failed" and trail["first_bad_seq"] == bad and trail["reason"] == why


def test_non_string_ids_and_verdicts_are_ignored_not_a_crash(tmp_path):
    """Model output where an id or a verdict value is a list / dict / number renders as text, never a TypeError."""
    from types import SimpleNamespace

    from asa import case_page
    from asa.console.load import AlertRun

    data = SimpleNamespace(by_id={})
    odd = {"alert_id": "A-007", "verdict": ["malicious"], "confidence": "low", "claims": [], "usage": {},
           "injection_reports": [{"event_id": ["E-000001"], "field": "x", "excerpt": "y"}, {"event_id": {"a": 1}}],
           "recommended_actions": [{"id": ["ACT-001"], "action": "x"}, {"id": {"a": 1}}, {"id": "ACT-002"}]}
    assert "E-000001" in case_page.injection_html(odd, data)
    assert "ACT-002" in case_page.actions_html(odd, {"ACT-002": {"by": "Night Lead", "at": "2026-10-29T05:00:00Z"}})
    run = AlertRun(alert_id="A-007", run_dir=tmp_path, verdict=odd,
                   intel={"indicators": [{"verdict": {"x": 1}}, {"verdict": ["contain"]}, {"verdict": "contain"}]})
    assert pages.intel_counts(run) == {"contain": 1, "review": 0, "clear": 0}
    site = pages.Site(run_id=RUN_ID, alert_ids={"A-007"})
    assert "A-007" in pages.queue_page(site, [run], {}, {})
