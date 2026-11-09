"""The write-ups must not drift from the recorded results or point at files that are not there."""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ["README.md", "SECURITY.md", "THIRD_PARTY.md", "docs/brief.md", "docs/cases.md", "docs/decisions.md", "docs/pilot-readout.md", "docs/usage.md"]


def results() -> dict:
    return json.loads((ROOT / "evals" / "results.json").read_text(encoding="utf-8"))


def text(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_readme_result_table_matches_results_json():
    t, i, readme = results()["triage"], results()["injection"], text("README.md")
    assert (t["n"], t["planned"], t["incomplete"]) == (30, 30, False)
    acc, base = t["accuracy"], t["baseline"]
    assert f"**{acc['correct']} of {acc['n']} ({acc['rate']:.0%})**" in readme
    assert f"**{base['correct']} of {base['n']} ({base['rate']:.0%})**" in readme
    assert f"| 30 | {t['needs_human']['k']} (the key expects {sum(t['confusion']['needs_human'].values())}) |" in readme
    assert f"**{i['reported']} of {i['n']}** reported; **{i['followed']}** followed" in readme
    u = t["unsupported_claims"]
    assert f"| {u['n']} claims, {u['runs']} runs | **{u['k']}** |" in readme
    c = t["cost_usd"]
    assert f"mean **${c['mean']:.3f}**, max ${c['max']:.3f} (total ${c['total']:.2f})" in readme
    assert f"**n_malicious = {t['n_malicious']}.**" in readme
    assert t["models"] == ["claude-sonnet-5-5"] and t["efforts"] == {"high": 30}
    assert "`claude-sonnet-5-5`, reasoning effort `high` for all 30 alerts" in readme


@pytest.mark.parametrize("name", ["docs/pilot-readout.md", "docs/cases.md"])
def test_other_docs_quote_the_same_numbers(name):
    t, doc = results()["triage"], text(name)
    assert "20 of 30" in doc and "15 of 30" in doc and "n_malicious = 1" in doc
    assert f"${t['cost_usd']['mean']:.3f}" in doc and f"${t['cost_usd']['max']:.3f}" in doc
    assert f"0 unsupported claims in {t['unsupported_claims']['n']} claims" in doc or f"0 of {t['unsupported_claims']['n']} claims" in doc


@pytest.mark.parametrize("name", DOCS)
def test_relative_links_resolve(name):
    base = (ROOT / name).parent
    for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", text(name)) + re.findall(r'src="([^"]+)"', text(name)):
        if re.match(r"[a-z]+:", target):
            continue
        assert (base / target).resolve().is_file(), f"{name}: {target} does not exist"


def test_readme_has_the_ai_use_line_and_no_process_remnants():
    readme = text("README.md")
    assert "<!--" not in readme
    assert "Designed, specified and reviewed by me; most code written by Claude Code agents I directed." in readme


def test_license_is_mit_with_a_holder():
    lic = text("LICENSE")
    assert lic.startswith("MIT License") and re.search(r"Copyright \(c\) 2026 \S+", lic)


def test_svgs_are_text_only_and_self_contained():
    for name in ("architecture",):
        svg = text(f"docs/img/{name}.svg")
        assert svg.startswith("<svg") and "<script" not in svg and "http://" not in svg.replace("http://www.w3.org/2000/svg", "")
        assert "<image" not in svg and "<foreignObject" not in svg


@pytest.mark.parametrize("image", ["hero.png", "trust-report.png"])
def test_png_has_no_text_or_metadata_chunks(image):
    import struct

    data = (ROOT / "docs" / "img" / image).read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    kinds, pos = [], 8
    while pos < len(data):
        size, kind = struct.unpack(">I4s", data[pos:pos + 8])
        kinds.append(kind.decode())
        pos += 12 + size
    assert kinds[0] == "IHDR" and kinds[-1] == "IEND"
    assert not {"tEXt", "iTXt", "zTXt", "eXIf", "tIME"} & set(kinds)


def test_gitattributes_keeps_lf_so_recordings_hash_the_same_on_windows():
    assert "* text=auto eol=lf" in text(".gitattributes").splitlines()


# ---- asa2-d: the trust-first README, the ADRs, the media and the wording rules ----


def test_readme_first_lines_say_synthetic_pilot():
    head = " ".join(text("README.md").splitlines()[:6]).lower()
    assert "synthetic pilot" in head and "not a product" in head


def test_readme_order_hero_then_story_then_try_then_checklist():
    readme = text("README.md")
    marks = ["docs/img/hero.png", "## The question a buyer asks", "## Try it in 30 seconds", "docs/img/tamper.gif", "## The buyer's checklist",
             "## What the numbers say", "## What failed and what I changed", "## How this plugs into a real SOC", "## Honest limits"]
    at = [readme.index(m) for m in marks]
    assert at == sorted(at), dict(zip(marks, at))
    assert "asa demo" in readme[at[2]:at[4]] and "asa audit verify" in readme[at[2]:at[4]]


def test_first_screen_puts_the_limits_next_to_the_trust_numbers():
    first = text("README.md").split("## The question a buyer asks")[0]
    for needle in ("20 of 30", "15 of 30", "20** to a person", "expects 10", "**1** malicious", "self-declared", "0 unsupported claims in 86", "6 of 6 planted injections reported, 0 followed"):
        assert needle in first, needle


def test_readme_pins_the_demo_anchor_that_test_demo_checks():
    demo = text("tests/test_demo.py")
    lines, head = re.search(r'DEMO_A007_ANCHOR = \((\d+), "([0-9a-f]{64})"\)', demo).groups()
    readme = text("README.md")
    assert f"--head {head} --lines {lines}" in readme
    assert f"{lines} lines" in readme and f"seq 17" in readme


def test_one_recording_date_everywhere():
    """The folder id says 2026-10-28 (US Pacific evening); the files stamp it in UTC as 2026-10-29. A bare 2026-10-29 line must say UTC."""
    for name in DOCS:
        for line in text(name).splitlines():
            if "2026-10-29" in line:
                assert "UTC" in line, f"{name}: {line.strip()[:100]}"
    assert "2026-10-28" in text("README.md") and "2026-10-28" in text("docs/pilot-readout.md")


def test_generated_results_and_docs_agree_on_the_recording_date():
    """One reader-facing date: the one in the recording id. Generated text takes it from there, so it cannot drift."""
    from asa.common import recording_date

    t = results()["triage"]
    date = recording_date(t["recording"])
    assert date == "2026-10-28" and t["recorded_dates"] == [date]
    assert f"recorded {date}" in text("evals/results.md")
    for name in DOCS + ["evals/results.md"]:
        assert not re.search(r"recorded (on )?2026-10-29", text(name)), name
    for name in ("README.md", "docs/pilot-readout.md", "docs/usage.md"):
        assert date in text(name), name


def test_recording_date():
    from asa.common import recording_date

    assert recording_date("live-20261028") == "2026-10-28"
    for bad in ("fixture", "live-2026102", "live-20261028x", None, 20261028):
        assert recording_date(bad) is None


def test_roadmap_line_names_no_framework_detail():
    readme = text("README.md")
    assert "a private evaluation framework for AI agent work (in progress)" in readme
    assert readme.count("private evaluation framework") == 1


def test_decisions_have_the_four_trust_adrs_in_order():
    heads = re.findall(r"^## (\d+)\. (.+)$", text("docs/decisions.md"), re.M)
    assert [int(n) for n, _ in heads] == list(range(1, len(heads) + 1)) and len(heads) >= 13
    titles = {int(n): t.lower() for n, t in heads}
    assert "hash chain" in titles[10] and "static console" in titles[11] and "after triage" in titles[12] and "fixtures" in titles[13]
    assert "tamper-evident, not tamper-proof" in text("docs/decisions.md")


def test_security_md_has_the_audit_and_console_notes():
    sec = text("SECURITY.md")
    for head in ("## The audit trail (threat notes)", "## The console (threat notes)"):
        assert head in sec
    assert "tamper-evident, not tamper-proof" in sec and "default-src 'none'" in sec


def test_pilot_readout_has_the_trust_section_with_its_limits():
    doc = text("docs/pilot-readout.md")
    assert "## What the trust layer adds" in doc and "30 of 30" in doc and "seq 17" in doc and "does **not** show" in doc


def _gif_blocks(data: bytes):
    """Yield (kind, size) for each block of a GIF: 'image', ('ext', label)."""
    assert data[:6] in (b"GIF87a", b"GIF89a")
    flags = data[10]
    pos = 13 + (3 * 2 ** ((flags & 7) + 1) if flags & 0x80 else 0)
    width, height = int.from_bytes(data[6:8], "little"), int.from_bytes(data[8:10], "little")
    blocks = []
    while data[pos] != 0x3B:
        if data[pos] == 0x21:
            label, pos = data[pos + 1], pos + 2
            blocks.append(("ext", label))
        elif data[pos] == 0x2C:
            flags2 = data[pos + 9]
            pos += 10 + (3 * 2 ** ((flags2 & 7) + 1) if flags2 & 0x80 else 0) + 1
            blocks.append(("image", 0))
        else:
            raise AssertionError("bad GIF block")
        while data[pos]:
            pos += data[pos] + 1
        pos += 1
    return width, height, blocks


def test_tamper_gif_is_small_looping_and_has_no_comment_or_application_metadata():
    data = (ROOT / "docs" / "img" / "tamper.gif").read_bytes()
    width, height, blocks = _gif_blocks(data)
    kinds = blocks
    assert sum(1 for k, _ in kinds if k == "image") >= 3
    labels = {label for k, label in kinds if k == "ext"}
    assert 0xFE not in labels, "GIF comment block"
    assert labels <= {0xF9, 0xFF}  # graphic control, and the NETSCAPE loop extension only
    assert width <= 1280 and len(data) < 400_000
    if 0xFF in labels:
        assert b"NETSCAPE2.0" in data and data.count(b"\x21\xff\x0b") == 1


def test_images_in_the_readme_exist_and_have_alt_text():
    readme = text("README.md")
    imgs = re.findall(r'!\[([^\]]*)\]\((docs/img/[^)]+)\)', readme) + [(a, s) for s, a in re.findall(r'<img src="(docs/img/[^"]+)" alt="([^"]*)"', readme)]
    assert {s for _, s in imgs} >= {"docs/img/hero.png", "docs/img/tamper.gif", "docs/img/trust-report.png", "docs/img/architecture.svg"}
    for alt, src in imgs:
        assert len(alt) > 20 and (ROOT / src).is_file(), src


def test_no_internal_video_note_is_shipped():
    assert not (ROOT / "docs" / "shot-list.md").exists() and "shot-list" not in text("README.md")
