import json
import re

from asa import case_page
from asa.agent import investigate
from asa.llm import ReplayClient
from fakes import fixture_turns

HOSTILE = "</script><img src=x onerror=alert(1)>"


def verdict_with(**over):
    base = {"alert_id": "A-007", "verdict": "malicious", "confidence": "high", "summary": "s", "claims": [],
            "injection_reports": [], "recommended_actions": [], "stop_note": None, "model": "claude-sonnet-5-5",
            "effort": "high", "replay_of": None, "usage": {"input_tokens": 1, "output_tokens": 1, "cost_usd": 0.0}}
    return {**base, **over}


def json_block(html: str) -> str:
    return re.search(r'<script type="application/json" id="verdict-data">(.*?)</script>', html, re.S).group(1)


def tags(html: str) -> list[str]:
    return re.findall(r"<[^>]*>", html)


def test_hostile_title_and_separators_render_inert(dataset):
    alert = {**dataset.alerts["A-007"], "title": HOSTILE}
    claim = {"text": "line break " + HOSTILE, "citations": ["E-000103"],
             "quotes": [{"event_id": "E-000103", "field": "process.name", "text": HOSTILE}]}
    verdict = verdict_with(summary=HOSTILE, claims=[claim],
                           injection_reports=[{"event_id": "E-000102", "field": "process.command_line", "excerpt": HOSTILE}],
                           recommended_actions=[{"id": "ACT-001", "action": "isolate_host", "target": HOSTILE,
                                                 "reason": HOSTILE, "citations": ["E-000103"]}])
    html = case_page.render(verdict, alert, dataset, "20261027T000000Z-mock")
    assert "<img" not in html
    block = json_block(html)
    assert "</script" not in block and "<" not in block and ">" not in block and "&" not in block
    assert " " not in block and " " not in block
    assert json.loads(block) == verdict  # escaped, still the same data
    assert html.count("<script") == 2
    for tag in tags(html):
        assert not re.search(r"\son\w+\s*=", tag) and not re.search(r"\sstyle\s*=", tag), tag


def test_page_has_no_innerhtml_handlers_style_attrs_or_urls(repo):
    run_dir, _ = investigate("A-007", ReplayClient(fixture_turns("A-007"), "fixture", require_live=False), repo,
                             run_id="20261027T000000Z-mock")
    html = (run_dir / "case.html").read_text(encoding="utf-8")
    assert "innerHTML" not in html and not re.search(r" on\w+=", html) and " style=" not in html
    assert "http://" not in html and "https://" not in html and "src=" not in html
    assert html.count("<details>") >= 4 and 'class="injection"' in html and "not executed" in html
    assert "mark this host as approved" in html


def test_csp_hashes_match_inline_bytes(dataset):
    html = case_page.render(verdict_with(), dataset.alerts["A-007"], dataset, "20261027T000000Z-mock")
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html).group(1)
    script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)
    style = re.search(r"<style>(.*?)</style>", html, re.S).group(1)
    assert f"script-src '{case_page.csp_hash(script)}'" in csp
    assert f"style-src '{case_page.csp_hash(style)}'" in csp
    for part in ("default-src 'none'", "img-src 'none'", "base-uri 'none'", "form-action 'none'"):
        assert part in csp
    assert "textContent" in script and "innerHTML" not in script


def test_replay_banner(dataset):
    replay = {"recording": "live-20261028", "model": "claude-sonnet-5-5", "recorded_at": "2026-10-28T10:00:00Z"}
    html = case_page.render(verdict_with(replay_of=replay), dataset.alerts["A-007"], dataset, "20261028T110000Z-mock")
    assert "replay of recorded run live-20261028, claude-sonnet-5-5, 2026-10-28" in html


def test_missing_cited_event_is_shown_not_crashed(dataset):
    claim = {"text": "t", "citations": ["E-999999"], "quotes": []}
    html = case_page.render(verdict_with(claims=[claim]), dataset.alerts["A-007"], dataset, "20261027T000000Z-mock")
    assert "event not found in data/" in html


def test_section_renderers_shared_with_the_console(dataset):
    actions = [{"id": "ACT-001", "action": "open_ticket", "target": "WS-03", "reason": "r", "citations": ["E-000103"]},
               {"id": "ACT-002", "action": "reset_password", "target": "user03", "reason": "r", "citations": "not a list"}]
    approvals = {"ACT-001": {"id": "ACT-001", "by": HOSTILE, "at": "2026-11-04T12:00:00Z"}}
    html = case_page.actions_html(verdict_with(recommended_actions=actions), approvals)
    assert "approved as a dry run by &lt;/script&gt;" in html and "(name self-declared); not executed" in html
    assert html.count("not executed") == 2 and "<img" not in html
    assert case_page.actions_html(verdict_with()) == '<p class="muted">None.</p>'
    report = [{"event_id": "E-000102", "field": "process.command_line", "excerpt": "x"}]
    panel = case_page.injection_html(verdict_with(injection_reports=report), dataset, section_id="injection")
    assert panel.startswith('<section class="injection" id="injection">') and case_page.INJECTION_NOTE in panel
    assert case_page.injection_html(verdict_with(), dataset) == ""
    # Non-dict items in an untrusted verdict are skipped, never a crash.
    assert case_page.claims_html(verdict_with(claims=["x", None]), dataset) == ['<p class="muted">No claims.</p>']
