"""Reconcile tab for the Streamlit demo: how it works, a live playground, and the month's real results."""
from __future__ import annotations

import json
import re
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pandas as pd
import streamlit as st

from agentguard.reconcile import (
    PaymentApproved, PaymentObserved, PaymentSubmitted, ReconConfig, Status, reconcile,
)

ROOT = Path(__file__).resolve().parent
DB = ROOT / "data" / "agentguard.db"

STATUS_HE = {
    "CONFIRMED": "שולם כמו שאושר", "PENDING": "עדיין בדרך", "FAILED": "נכשל, לא יצא כסף",
    "MISSING": "אושר אבל לא יצא", "DUPLICATE": "שולם יותר מפעם אחת", "AMOUNT_MISMATCH": "סכום שונה ממה שאושר",
    "DESTINATION_MISMATCH": "נשלח לכתובת אחרת", "UNAPPROVED_OUTFLOW": "כסף יצא בלי אישור",
}
COLOR = {"none": "#1f7a3a", "low": "#5b6b7a", "medium": "#b26b00", "high": "#c0392b", "critical": "#7b1010"}


def rtl(md: str) -> None:
    # Markdown is not parsed inside an HTML block, so translate the bits we use.
    html = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", md)
    html = re.sub(r"`([^`]+)`", r"<code>\1</code>", html)
    if html.startswith("### "):
        html = f"<h3>{html[4:]}</h3>"
    st.markdown(f"<div dir='rtl' style='text-align:right'>{html}</div>", unsafe_allow_html=True)


def badge(status: str, severity: str) -> None:
    st.markdown(
        f"<div style='padding:12px 14px;border-radius:8px;background:{COLOR[severity]};color:white'>"
        f"<div style='font-size:20px;font-weight:600'>{status}</div>"
        f"<div dir='rtl' style='font-size:14px'>{STATUS_HE[status]} · חומרה: {severity}</div></div>",
        unsafe_allow_html=True)


def short(a: str) -> str:
    return f"{a[:6]}…{a[-4:]}" if a and len(a) > 12 else a


# ------------------------------------------------------------------ 1. how it works


def how_it_works() -> None:
    rtl("### איך זה עובד")
    rtl("המנוע של שלב 1–2 מחליט <b>לפני</b> החתימה אם מותר לשלם. Reconcile בודק <b>אחרי</b> הביצוע: "
        "האם מה שקרה בפועל בבלוקצ'יין זהה למה שאושר. שני הצדדים נדרשים: הבלוקצ'יין לא יודע מה אושר, "
        "והאישור לא יודע מה בוצע.")
    cols = st.columns(4)
    steps = [
        ("1 · Approve", "רושמים מה אושר", "סכום, מטבע, רשת, כתובת יעד, ארנק הסוכן ומזהה הבקשה. מגיע מהחלטות APPROVE של המנוע."),
        ("2 · Observe", "קוראים מה קרה", "העברות USDC שיצאו מארנק הסוכן, מתוך הבלוקצ'יין. אופציונלי: המבצע מדווח איזה tx_hash שלח."),
        ("3 · Reconcile", "משווים", "מקשרים כל העברה לאישור (לפי tx_hash, ואם אין, לפי ארנק+יעד+סכום+זמן) ובודקים סכום, יעד, כפילות וסופיות."),
        ("4 · Explain", "מסבירים ופועלים", "לכל חריגה: סטטוס, הסבר, פעולה מומלצת וחבילת ראיות שמחברת אישור, החלטה וביצוע."),
    ]
    for col, (title, he_title, body) in zip(cols, steps):
        with col:
            st.markdown(f"<div style='border:1px solid #c9ced6;border-radius:8px;padding:12px;height:100%'>"
                        f"<div style='font-weight:600'>{title}</div>"
                        f"<div dir='rtl' style='font-weight:600;margin-top:4px'>{he_title}</div>"
                        f"<div dir='rtl' style='font-size:13px;margin-top:6px'>{body}</div></div>",
                        unsafe_allow_html=True)
    with st.expander("8 התוצאות האפשריות"):
        rows = [(s, STATUS_HE[s.value], sev) for s, sev in [
            (Status.CONFIRMED, "none"), (Status.PENDING, "low"), (Status.FAILED, "medium"), (Status.MISSING, "high"),
            (Status.DUPLICATE, "high"), (Status.AMOUNT_MISMATCH, "high"), (Status.DESTINATION_MISMATCH, "critical"),
            (Status.UNAPPROVED_OUTFLOW, "critical")]]
        st.dataframe(pd.DataFrame([{"status": s.value, "משמעות": he, "severity": sev} for s, he, sev in rows]),
                     hide_index=True, width="stretch")


# ------------------------------------------------------------------ 2. playground

T = datetime(2026, 10, 10, 9, 0, tzinfo=timezone.utc)
WALLET = "0x14ec54a966fb83430b43ec844ace015863326488"
ACME = "0x7a3fc1e5d2b9846f0e1c2a3b4d5e6f708192a4b1"
THIEF = "0xa742c09e7f2a8b3c6d5e4f1a2b3c4d5e6f7a1763"
B0 = 51_000_000

SCENARIOS = {
    "שולם כמו שצריך": "clean",
    "המבצע שילם פעמיים (retry)": "duplicate",
    "באג בספרות עשרוניות (750 במקום 75)": "decimals",
    "הכתובת הוחלפה אחרי האישור": "swap",
    "התשלום לא יצא בכלל": "missing",
    "עדיין בדרך (מעט אישורים)": "pending",
    "ההעברה נכשלה (revert)": "reverted",
    "כסף יצא מהארנק בלי שום אישור": "bypass",
}


def _obs(h, amount="75", to=ACME, sec=20, status="success"):
    when = T + timedelta(seconds=sec)
    return PaymentObserved(chain="base", tx_hash=h, block_number=B0 + sec // 2, block_time=when, token="USDC",
                           from_address=WALLET, to_address=to, amount=Decimal(amount), status=status)


def playground() -> None:
    rtl("### נסי בעצמך")
    rtl("בחרי מה קרה בפועל, וראי מה המערכת מקבלת ומה היא מחליטה. החישוב רץ עכשיו, באותו קוד שרץ על כל החודש.")
    c1, c2 = st.columns([3, 2])
    label = c1.selectbox("מה קרה בפועל?", list(SCENARIOS), key="pg_scenario")
    reported = c2.checkbox("המבצע דיווח איזה tx_hash שלח", value=True, key="pg_reported")
    kind = SCENARIOS[label]

    approved = [] if kind == "bypass" else [PaymentApproved(
        request_id="REQ-DEMO", approved_at=T, agent_id="agent-billing-01", mandate_id="MND-101",
        from_wallet=WALLET, to_address=ACME, amount=Decimal("75"), token="USDC", chain="base")]
    observed = {
        "clean": [_obs("0xaaa1")],
        "duplicate": [_obs("0xaaa1"), _obs("0xaaa2", sec=200)],
        "decimals": [_obs("0xaaa1", amount="750")],
        "swap": [_obs("0xaaa1", to=THIEF)],
        "missing": [],
        "pending": [_obs("0xaaa1")],
        "reverted": [_obs("0xaaa1", status="reverted")],
        "bypass": [_obs("0xbad1", amount="240", to=THIEF)],
    }[kind]
    submitted = []
    if reported and kind not in ("bypass",):
        hashes = ["0xaaa1", "0xaaa2"] if kind == "duplicate" else ["0xaaa1"]
        submitted = [PaymentSubmitted(request_id="REQ-DEMO", tx_hash=h, submitted_at=T, attempt=i + 1)
                     for i, h in enumerate(hashes)]
    as_of = T + timedelta(hours=2)
    head = (B0 + 10 + 3) if kind == "pending" else B0 + 3600
    items = reconcile(approved, observed, submitted, as_of=as_of, heads={"base": head}, agent_wallets={WALLET},
                      cfg=ReconConfig())

    right, mid, left = st.columns(3)   # reversed: Hebrew reads right to left, so the flow starts on the right
    with left:
        rtl("**מה אושר (Approve)**")
        if approved:
            a = approved[0]
            st.markdown(f"`{a.request_id}` · {a.agent_id}  \n**{a.amount} {a.token}** on {a.chain}  \n"
                        f"to `{short(a.to_address)}` (Acme Cloud)  \nfrom agent wallet `{short(a.from_wallet)}`  \n"
                        f"approved {a.approved_at:%Y-%m-%d %H:%M} UTC")
        else:
            rtl("אין שום אישור לתשלום הזה.")
        if submitted:
            rtl("**דיווח המבצע (Submitted)**")
            st.markdown("  \n".join(f"attempt {s.attempt}: `{s.tx_hash}`" for s in submitted))
    with mid:
        rtl("**מה קרה בבלוקצ'יין (Observe)**")
        if observed:
            st.dataframe(pd.DataFrame([{
                "tx": o.tx_hash, "to": short(o.to_address) + (" (Acme)" if o.to_address == ACME else " (?)"),
                "amount": str(o.amount), "status": o.status, "block": o.block_number,
                "confirmations": max(0, head - o.block_number + 1)} for o in observed]),
                hide_index=True, width="stretch")
        else:
            rtl("לא נמצאה אף העברה מהארנק.")
        st.caption(f"Checked at {as_of:%H:%M} UTC (2 hours after approval). Needs 12 confirmations.")
    with right:
        rtl("**ההחלטה (Reconcile + Explain)**")
        for it in items:
            badge(it.status.value, it.severity)
            st.markdown(f"**Why:** {it.explanation}")
            st.markdown(f"**Action:** {it.action}")
            st.caption(f"Linked by: {it.match_method}")

    with st.expander("איך המערכת הגיעה להחלטה, שלב אחר שלב"):
        steps = [f"1. אספה {len(observed)} העברות שיצאו מארנק הסוכן `{short(WALLET)}` (העברות נכנסות מתעלמים מהן)."]
        if submitted:
            steps.append(f"2. המבצע דיווח {len(submitted)} tx_hash, אז קישרה את ההעברות לאישור לפי ה־hash (הקישור החזק).")
        elif approved:
            steps.append("2. לא דווח hash, אז חיפשה העברה מאותו ארנק, לאותה כתובת, באותו סכום בדיוק, "
                         "תוך 24 שעות מהאישור (קישור חלש יותר, וזה כתוב בהסבר).")
        else:
            steps.append("2. אין אישור שאפשר לקשר אליו.")
        steps.append("3. בדקה בסדר הזה: האם בוצע בכלל → האם נכשל → האם הכתובת זהה → האם הסכום זהה → "
                     "האם יש יותר מביצוע אחד → כמה אישורים (confirmations) יש.")
        steps.append("4. כל העברה שיצאה מהארנק ולא קושרה לשום אישור מדווחת כ־UNAPPROVED_OUTFLOW.")
        rtl("<br>".join(steps))
        if kind == "decimals" and not reported:
            rtl("<b>שימי לב:</b> בלי hash, העברה של 750 לא תואמת לאישור של 75, ולכן היא לא מקושרת אליו. "
                "התוצאה היא שתי התראות (חסר + יצא בלי אישור) במקום \"סכום שגוי\". זו המגבלה הידועה, "
                "וזו הסיבה לבקש מהמבצע לדווח hash.")


# ------------------------------------------------------------------ 3. the month's results


def _queries() -> dict[str, str]:
    text = (ROOT / "sql" / "analysis.sql").read_text(encoding="utf-8")
    out = {}
    for block in re.split(r"^-- name: ", text, flags=re.M)[1:]:
        name, body = block.split("\n", 1)
        out[name.strip()] = body.strip().rstrip(";")
    return out


def _has_recon() -> bool:
    if not DB.exists():
        return False
    con = sqlite3.connect(DB)
    try:
        return con.execute("SELECT name FROM sqlite_master WHERE name='recon_items'").fetchone() is not None
    finally:
        con.close()


def run_pipeline() -> None:
    for script in ("load_excel.py", "run_batch.py", "simulate_chain.py", "reconcile_batch.py"):
        subprocess.run([sys.executable, str(ROOT / "scripts" / script)], check=True, capture_output=True)


def month_results() -> None:
    rtl("### התוצאות על חודש אוקטובר")
    rtl("258 בקשות תשלום עברו דרך המנוע, 218 אושרו, והסימולטור יצר את מה ש\"קרה בבלוקצ'יין\", כולל תקלות "
        "שהוזרקו בכוונה. כאן רואים מה Reconcile מצא.")
    if not _has_recon():
        st.info("The reconciliation tables are not built yet.")
        if st.button("Run the full pipeline (about 15 seconds)"):
            with st.spinner("Excel → SQL → engine → chain → reconcile"):
                run_pipeline()
            st.rerun()
        return

    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    q = _queries()
    items = pd.read_sql_query("SELECT * FROM recon_items", con)
    total_appr = int((items["subject"] == "approval").sum())
    exc = items[items["status"] != "CONFIRMED"]
    summary = pd.read_sql_query(q["recon_summary"], con)
    k = st.columns(4)
    k[0].metric("Approved payments", total_appr)
    k[1].metric("Confirmed cleanly", int((items["status"] == "CONFIRMED").sum()))
    k[2].metric("Exceptions to handle", len(exc))
    k[3].metric("Net difference (USDC)", f"{summary['difference_usdc'].sum():,.2f}")

    rtl("**התאמה ברמת ארנק:** כמה אושר מול כמה באמת יצא מכל ארנק. בעולם תקין העמודה האחרונה היא 0.")
    wallets = pd.read_sql_query(q["wallet_reconciliation"], con)
    wallets["wallet_address"] = wallets["wallet_address"].map(short)
    st.dataframe(wallets, hide_index=True, width="stretch")

    rtl("**לפי סוג תוצאה**")
    st.dataframe(summary, hide_index=True, width="stretch")

    rtl("**תור החריגות:** מה צוות התפעול צריך לטפל בו, מהחמור ביותר.")
    queue = pd.read_sql_query(q["recon_exceptions"], con)
    st.dataframe(queue[["severity", "status", "request_id", "agent_id", "payee_name", "approved_amount",
                        "match_method", "explanation"]], hide_index=True, width="stretch")

    rtl("### צלילה לתשלום אחד")
    if queue.empty:
        return
    opts = [f"{r.request_id if pd.notna(r.request_id) else 'no approval'} · {r.status} · "
            f"{r.payee_name if pd.notna(r.payee_name) else 'unknown wallet'}" for r in queue.itertuples()]
    pick = st.selectbox("Exception", range(len(opts)), format_func=lambda i: opts[i], key="recon_pick")
    row = {k: (None if pd.isna(v) else v) for k, v in queue.iloc[pick].items()}
    item = items[items["item_id"] == row["item_id"]].iloc[0]
    ev = json.loads(item["evidence"])

    c3, c2, c1 = st.columns(3)   # reversed for right-to-left reading
    with c1:
        rtl("**הבקשה וההחלטה לפני החתימה**")
        if row["request_id"]:
            req = dict(con.execute("SELECT * FROM payment_requests WHERE request_id=?", (row["request_id"],)).fetchone())
            dec = dict(con.execute("SELECT * FROM decisions WHERE request_id=?", (row["request_id"],)).fetchone())
            st.markdown(f"`{req['request_id']}` · {req['ts']} UTC  \n{req['agent_id']} → **{req['payee_name']}**  \n"
                        f"**{req['amount']} {req['token']}** to `{short(req['to_address'])}`  \nmandate `{req['mandate_id']}`  \n"
                        f"engine: **{dec['decision']}** ({dec['primary_reason']})")
            audit = con.execute("SELECT seq, record_hash FROM audit_log WHERE request_id=?", (row["request_id"],)).fetchone()
            if audit:
                st.caption(f"Audit record #{audit['seq']} · {audit['record_hash'][:16]}…")
        else:
            rtl("אין בקשה ואין אישור. הכסף יצא מחוץ למנוע.")
    with c2:
        rtl("**מה קרה בבלוקצ'יין**")
        obs = ev.get("observed", []) + ev.get("duplicates", []) + ([ev["transfer"]] if "transfer" in ev else [])
        if obs:
            st.dataframe(pd.DataFrame([{"tx": o["tx_hash"][:14] + "…", "to": short(o["to_address"]),
                                        "amount": o["amount"], "status": o["status"], "block": o["block_number"]}
                                       for o in obs]), hide_index=True, width="stretch")
        else:
            rtl("לא נמצאה העברה.")
        if ev.get("submitted_tx_hashes"):
            st.caption("Executor reported: " + ", ".join(h[:14] + "…" for h in ev["submitted_tx_hashes"]))
    with c3:
        rtl("**ההחלטה**")
        badge(item["status"], item["severity"])
        st.markdown(f"**Why:** {item['explanation']}")
        st.markdown(f"**Action:** {item['action']}")
    with st.expander("Evidence bundle (JSON)"):
        st.json(ev, expanded=False)
    con.close()


def render_reconcile() -> None:
    how_it_works()
    st.divider()
    playground()
    st.divider()
    month_results()
