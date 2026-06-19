#!/usr/bin/env python3
"""generate_report.py — turn rls_audit.sql findings into a client-grade HTML/PDF report.

Pipeline:
    psql "$DATABASE_URL" -t -A -F',' -f audit/rls_audit.sql > findings.csv
    python3 report/generate_report.py findings.csv --client "Acme Corp" --out report.html

Produces a self-contained, brandable HTML report (no external assets). Open it in a browser and
"Print → Save as PDF" for the deliverable, OR pass --pdf if you have `weasyprint`/`wkhtmltopdf`.

Deliberately dependency-light: the stdlib does everything. The PDF step is optional + auto-detected
so the report ALWAYS generates (HTML), and upgrades to PDF only if a renderer is present.
"""
import argparse, csv, datetime, html, shutil, subprocess, sys, tempfile
from pathlib import Path

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "INFO"]
SEV_COLOR = {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "INFO": "#3498db"}
SEV_BLURB = {
    "CRITICAL": "A tenant can read or write another tenant's data today. Fix before launch.",
    "HIGH": "A likely isolation gap or privilege-escalation surface. Fix before scaling.",
    "MEDIUM": "A hardening gap (defense-in-depth) or drift risk. Schedule it.",
    "INFO": "Posture metric, not a defect.",
}


def load_findings(path):
    rows = []
    with open(path, newline="") as f:
        for r in csv.reader(f):
            if not r or len(r) < 4:
                continue
            # severity, check, object, detail, remediation (remediation may contain commas → rejoin)
            sev, chk, obj, detail = r[0].strip(), r[1].strip(), r[2].strip(), r[3].strip()
            remediation = ",".join(r[4:]).strip() if len(r) > 4 else ""
            if sev not in SEV_ORDER:
                continue
            rows.append(dict(severity=sev, check=chk, object=obj, detail=detail, remediation=remediation))
    return rows


def esc(s):
    return html.escape(str(s or ""))


def build_html(rows, client, date_str):
    counts = {s: sum(1 for r in rows if r["severity"] == s) for s in SEV_ORDER}
    defects = counts["CRITICAL"] + counts["HIGH"] + counts["MEDIUM"]
    posture = next((r["detail"] for r in rows if r["check"] == "posture"), "")

    # readiness verdict (honest, not theatre)
    if counts["CRITICAL"] > 0:
        verdict, vcolor = "NOT LAUNCH-READY", SEV_COLOR["CRITICAL"]
        vline = f"{counts['CRITICAL']} CRITICAL cross-tenant exposure(s) must be closed before any tenant onboards."
    elif counts["HIGH"] > 0:
        verdict, vcolor = "HARDENING NEEDED", SEV_COLOR["HIGH"]
        vline = f"No CRITICAL leaks, but {counts['HIGH']} HIGH isolation gap(s) to close before scaling beyond the first tenant."
    else:
        verdict, vcolor = "LAUNCH-READY (RLS posture)", "#27ae60"
        vline = "No CRITICAL or HIGH RLS findings. Address any MEDIUM hardening items on schedule."

    cards = "".join(
        f'<div class="card" style="border-top:4px solid {SEV_COLOR[s]}">'
        f'<div class="n" style="color:{SEV_COLOR[s]}">{counts[s]}</div><div class="lbl">{s}</div></div>'
        for s in SEV_ORDER
    )

    sections = ""
    for s in SEV_ORDER:
        srows = [r for r in rows if r["severity"] == s and r["check"] != "posture"]
        if not srows:
            continue
        body = "".join(
            f"<tr><td class=chk>{esc(r['check'])}</td><td class=obj>{esc(r['object'])}</td>"
            f"<td>{esc(r['detail'])}</td><td class=fix>{esc(r['remediation'])}</td></tr>"
            for r in srows
        )
        sections += (
            f'<h2 style="color:{SEV_COLOR[s]}">{s} <span class=cnt>({len(srows)})</span></h2>'
            f'<p class=blurb>{esc(SEV_BLURB[s])}</p>'
            f'<table><thead><tr><th>Check</th><th>Object</th><th>Why it matters</th><th>Remediation</th></tr></thead>'
            f'<tbody>{body}</tbody></table>'
        )

    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<title>Multi-Tenant RLS Readiness Audit — {esc(client)}</title>
<style>
 body{{font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:#1a1a2e;max-width:880px;margin:2rem auto;padding:0 1.5rem}}
 h1{{font-size:1.6rem;margin:0 0 .2rem}} .sub{{color:#666;margin:0 0 1.5rem}}
 .verdict{{background:{vcolor};color:#fff;padding:1rem 1.2rem;border-radius:8px;margin:1rem 0}}
 .verdict b{{font-size:1.15rem}} .cards{{display:flex;gap:.8rem;margin:1.2rem 0}}
 .card{{flex:1;background:#f7f7fb;border-radius:8px;padding:.9rem;text-align:center}}
 .card .n{{font-size:1.9rem;font-weight:700}} .card .lbl{{font-size:.75rem;color:#666;letter-spacing:.5px}}
 h2{{margin:1.6rem 0 .2rem;font-size:1.15rem}} .cnt{{color:#999;font-weight:400}}
 .blurb{{color:#555;margin:.1rem 0 .6rem;font-size:.9rem}}
 table{{width:100%;border-collapse:collapse;font-size:.83rem;margin-bottom:.5rem}}
 th{{text-align:left;background:#1a1a2e;color:#fff;padding:.4rem .5rem;font-weight:600}}
 td{{padding:.4rem .5rem;border-bottom:1px solid #eee;vertical-align:top}}
 td.chk{{font-family:ui-monospace,monospace;font-size:.78rem;white-space:nowrap}}
 td.obj{{font-family:ui-monospace,monospace;font-size:.78rem}} td.fix{{font-family:ui-monospace,monospace;font-size:.75rem;color:#1a6}}
 .posture{{background:#eef;border-radius:6px;padding:.6rem .9rem;font-size:.85rem;margin:.5rem 0}}
 footer{{margin-top:2.5rem;padding-top:1rem;border-top:1px solid #eee;color:#888;font-size:.78rem}}
 @media print{{body{{margin:0}} .verdict{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
   th,.card .n{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}}}
</style></head><body>
<h1>Multi-Tenant RLS Readiness Audit</h1>
<p class=sub>Prepared for <b>{esc(client)}</b> · {esc(date_str)} · read-only schema audit (no row data accessed)</p>
<div class=verdict><b>{verdict}</b><br>{esc(vline)}</div>
<div class=posture>📊 {esc(posture)}</div>
<div class=cards>{cards}</div>
{sections}
<footer>
 <b>Method.</b> This audit inspects Postgres catalog metadata only (pg_class, pg_policies, pg_proc,
 information_schema) — it never reads, writes, or modifies your data or policies. The 7 checks target
 the failure modes that actually leak tenant data: RLS disabled, RLS-on-but-no-policy, permissive
 USING(true), write policies without WITH CHECK, tables with no tenant column, SECURITY DEFINER
 functions with a mutable search_path, and anon write grants.<br><br>
 <b>Caveat (honest).</b> A finding flags a <i>pattern worth a human's eyes</i>, not a guaranteed bug —
 e.g. a USING(true) on a deliberately-shared reference table, or a no-WITH-CHECK on a read-only ALL
 policy, are intentional. The value is the triaged shortlist + the exact remediation SQL, not a
 verdict that replaces review. Re-run after fixes to confirm closure.<br><br>
 Audit by <a href="https://github.com/Kaiser9005">Kaiser9005</a>.
</footer>
</body></html>"""


def main():
    ap = argparse.ArgumentParser(description="Generate an RLS-readiness audit report from findings.csv")
    ap.add_argument("findings", help="CSV from rls_audit.sql (severity,check,object,detail,remediation)")
    ap.add_argument("--client", default="Your Company", help="client name for the cover")
    ap.add_argument("--out", default="rls-audit-report.html", help="output HTML path")
    ap.add_argument("--pdf", action="store_true", help="also render a PDF (needs weasyprint or wkhtmltopdf)")
    ap.add_argument("--date", default=None, help="report date (default: today)")
    a = ap.parse_args()

    if not Path(a.findings).exists():
        sys.exit(f"findings file not found: {a.findings}")
    rows = load_findings(a.findings)
    if not rows:
        sys.exit("no parseable findings (expected: severity,check,object,detail,remediation per line)")

    date_str = a.date or datetime.date.today().isoformat()
    doc = build_html(rows, a.client, date_str)
    Path(a.out).write_text(doc, encoding="utf-8")
    print(f"✅ HTML report → {a.out}  ({len(rows)} findings)")

    if a.pdf:
        pdf_out = str(Path(a.out).with_suffix(".pdf"))
        if shutil.which("weasyprint"):
            subprocess.run(["weasyprint", a.out, pdf_out], check=True); print(f"✅ PDF → {pdf_out}")
        elif shutil.which("wkhtmltopdf"):
            subprocess.run(["wkhtmltopdf", a.out, pdf_out], check=True); print(f"✅ PDF → {pdf_out}")
        else:
            print("ℹ️  no PDF renderer found (install weasyprint or wkhtmltopdf). "
                  "Open the HTML and Print → Save as PDF instead.")


if __name__ == "__main__":
    main()
