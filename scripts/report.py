"""Export the SQL analysis to an Excel report.

    python scripts/report.py [database.db]      -> reports/agentguard_results.xlsx

Sheets: Summary (live Excel formulas over all_decisions), all_decisions (the joined
data), then one sheet per query in sql/analysis.sql.
"""
from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path

from openpyxl import Workbook
from openpyxl.formatting.rule import CellIsRule
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

ROOT = Path(__file__).resolve().parents[1]
DB = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "agentguard.db"
OUT = ROOT / "reports" / "agentguard_results.xlsx"

FONT = "Arial"
HEADER = PatternFill("solid", fgColor="1F3864")
FILLS = {"APPROVE": PatternFill("solid", fgColor="E2EFDA"), "REVIEW": PatternFill("solid", fgColor="FFF2CC"),
         "BLOCK": PatternFill("solid", fgColor="F8CBAD")}

ALL_DECISIONS_SQL = """
SELECT p.request_id, p.ts, p.agent_id, p.mandate_id, p.payee_name, p.to_address, p.amount,
       p.scenario_type, p.ground_truth, d.decision, d.risk_score, d.primary_reason, d.reason_codes
FROM payment_requests p JOIN decisions d USING (request_id)
ORDER BY p.ts, p.request_id
"""


def queries() -> list[tuple[str, str]]:
    text = (ROOT / "sql" / "analysis.sql").read_text(encoding="utf-8")
    out = []
    for block in re.split(r"^-- name: ", text, flags=re.M)[1:]:
        name, body = block.split("\n", 1)
        out.append((name.strip()[:31], body.strip().rstrip(";")))
    return out


def style_table(ws, ncols: int, widths: dict[int, int] | None = None) -> None:
    for c in ws[1]:
        c.font = Font(name=FONT, bold=True, color="FFFFFF")
        c.fill = HEADER
        c.alignment = Alignment(vertical="center", wrap_text=True)
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.font = Font(name=FONT, size=10)
    for i in range(1, ncols + 1):
        letter = get_column_letter(i)
        longest = max((len(str(c.value)) for c in ws[letter] if c.value is not None), default=8)
        ws.column_dimensions[letter].width = (widths or {}).get(i, min(max(10, longest + 2), 50))
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions


def color_decisions(ws, col_letters: list[str], last_row: int) -> None:
    for col in col_letters:
        rng = f"{col}2:{col}{last_row}"
        for word, fill in FILLS.items():
            ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=[f'"{word}"'], fill=fill))


def main() -> None:
    con = sqlite3.connect(DB)
    wb = Workbook()
    summary = wb.active
    summary.title = "Summary"

    # ------------------------------------------------ all_decisions (data for the Summary formulas)
    cur = con.execute(ALL_DECISIONS_SQL)
    cols = [d[0] for d in cur.description] + ["match"]
    data = cur.fetchall()
    ws = wb.create_sheet("all_decisions")
    ws.append(cols)
    for i, r in enumerate(data, start=2):
        ws.append(list(r) + [f'=IF(I{i}=J{i},"yes","no")'])
    n_last = len(data) + 1
    for row in ws.iter_rows(min_row=2, min_col=7, max_col=7):
        row[0].number_format = "#,##0.00"
    style_table(ws, len(cols), {6: 44, 13: 60})
    color_decisions(ws, ["I", "J"], n_last)
    ws.conditional_formatting.add(f"N2:N{n_last}", CellIsRule(operator="equal", formula=['"no"'],
                                                               fill=FILLS["BLOCK"]))

    # ------------------------------------------------ Summary (formulas, recalculated by Excel on open)
    T = f"all_decisions!$I$2:$I${n_last}"     # ground truth
    E = f"all_decisions!$J$2:$J${n_last}"     # engine decision
    A = f"all_decisions!$G$2:$G${n_last}"     # amount
    summary["A1"] = "AgentGuard batch results"
    summary["A1"].font = Font(name=FONT, bold=True, size=16)
    summary["A2"] = (f"Source: {DB.name}. Synthetic data written alongside the engine: shows rule coverage, "
                     "not real-world performance.")
    summary["A2"].font = Font(name=FONT, italic=True, size=9, color="595959")

    kpis = [
        ("Requests evaluated", f"=COUNTA({E})", "0"),
        ("Exact match with ground truth", f"=SUMPRODUCT(--({T}={E}))/B4", "0.0%"),
        ("Detection rate (should stop -> stopped)",
         f'=COUNTIFS({T},"<>APPROVE",{E},"<>APPROVE")/COUNTIF({T},"<>APPROVE")', "0.0%"),
        ("False positive rate (fine -> stopped)",
         f'=COUNTIFS({T},"APPROVE",{E},"<>APPROVE")/COUNTIF({T},"APPROVE")', "0.0%"),
        ("Missed (should stop -> approved)", f'=COUNTIFS({T},"<>APPROVE",{E},"APPROVE")', "0"),
        ("Blocked value (USDC)", f'=SUMIFS({A},{E},"BLOCK")', "#,##0.00"),
        ("Approved value (USDC)", f'=SUMIFS({A},{E},"APPROVE")', "#,##0.00"),
    ]
    summary["A3"], summary["B3"] = "Metric", "Value"
    for i, (label, formula, fmt) in enumerate(kpis, start=4):
        summary[f"A{i}"], summary[f"B{i}"] = label, formula
        summary[f"B{i}"].number_format = fmt

    top = 4 + len(kpis) + 1
    summary[f"A{top}"] = "Confusion matrix (rows = ground truth, columns = engine)"
    summary[f"A{top}"].font = Font(name=FONT, bold=True, size=11)
    hdr = top + 1
    labels = ["APPROVE", "REVIEW", "BLOCK"]
    summary.cell(hdr, 1, "should be \\ engine")
    for j, lab in enumerate(labels, start=2):
        summary.cell(hdr, j, lab)
    summary.cell(hdr, 5, "Total")
    for i, truth in enumerate(labels, start=hdr + 1):
        summary.cell(i, 1, truth)
        for j in range(2, 5):
            col = get_column_letter(j)
            summary.cell(i, j, f'=COUNTIFS({T},$A{i},{E},{col}${hdr})')
        summary.cell(i, 5, f"=SUM(B{i}:D{i})")

    for row in summary.iter_rows(min_row=3, max_row=hdr + 3):
        for c in row:
            if c.value is not None and c.font.size != 11:
                c.font = Font(name=FONT, size=10, bold=c.row in (3, hdr) or c.column == 1 and c.row > hdr)
    for c in list(summary[3]) + list(summary[hdr]):
        if c.value is not None:
            c.fill, c.font = HEADER, Font(name=FONT, bold=True, color="FFFFFF")
    summary.column_dimensions["A"].width = 44
    for col in "BCDE":
        summary.column_dimensions[col].width = 14
    summary[f"A{hdr + 5}"] = ("Formulas reference the all_decisions sheet: edit a ground_truth there and these "
                              "numbers update.")
    summary[f"A{hdr + 5}"].font = Font(name=FONT, italic=True, size=9, color="595959")

    # ------------------------------------------------ one sheet per SQL query
    skipped = []
    for name, sql in queries():
        try:
            cur = con.execute(sql)
        except sqlite3.OperationalError as e:   # e.g. reconcile tables not built yet
            skipped.append(f"{name} ({e})")
            continue
        qcols = [d[0] for d in cur.description]
        sheet = wb.create_sheet(name)
        sheet.append(qcols)
        rows = cur.fetchall()
        for r in rows:
            sheet.append(list(r))
        style_table(sheet, len(qcols))
        dec_cols = [get_column_letter(i + 1) for i, c in enumerate(qcols) if c in ("decision", "ground_truth",
                                                                                  "should_be", "expected")]
        color_decisions(sheet, dec_cols, len(rows) + 1)

    OUT.parent.mkdir(exist_ok=True)
    wb.save(OUT)
    print(f"wrote {OUT}")
    print(f"  sheets: {', '.join(wb.sheetnames)}")
    for sk in skipped:
        print(f"  skipped {sk}: run scripts/simulate_chain.py and scripts/reconcile_batch.py first")
    con.close()


if __name__ == "__main__":
    main()
