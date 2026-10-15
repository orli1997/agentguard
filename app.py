"""Streamlit demo.  streamlit run app.py"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from agentguard import ENGINE_VERSION, evaluate
from agentguard.audit import AuditLog
from agentguard.metrics import run as run_metrics
from agentguard.models import EvaluationRequest, EvaluationResult
from agentguard.scenarios import CASES, by_id
from agentguard.scenarios_phase2 import CASES2, NOW, by_id2

st.set_page_config(page_title="AgentGuard — Pre-Signing Risk Engine", layout="wide")
audit = AuditLog("agentguard_audit.db")

COLORS = {"APPROVE": "#1f7a3a", "REVIEW": "#b26b00", "BLOCK": "#b3261e"}
SEV_ICON = {"block": "⛔", "review": "⚠️", "info": "ℹ️"}

st.title("AgentGuard · Pre-Signing Risk Engine")
st.caption(f"engine {ENGINE_VERSION} · Phase 1: address injection · Phase 2: signed mandates, budgets, "
           "split payments · simulation only, no wallet, no real funds")


def show_result(req: EvaluationRequest, res: EvaluationResult, expected: str) -> None:
    rec = audit.record(req, res)
    dec = res.decision.value
    st.markdown(
        f"<div style='padding:14px;border-radius:8px;background:{COLORS[dec]};color:white;"
        f"font-size:24px;font-weight:600'>{dec}"
        f"<span style='font-size:14px;font-weight:400;margin-left:16px'>"
        f"experimental risk score {res.risk_score}/100 · {res.latency_ms} ms</span></div>",
        unsafe_allow_html=True)
    if dec != expected:
        st.warning(f"Differs from the case label ({expected}), which is expected if you edited inputs.")
    st.subheader("Findings")
    for f in res.findings:
        with st.expander(f"{SEV_ICON[f.severity.value]} {f.code} — {f.message}",
                         expanded=f.severity.value != "info"):
            st.json(f.evidence)
    st.caption(f"Audit record hash {rec['record_hash'][:16]}… (prev {rec['prev_hash'][:16]}…)")
    st.info("APPROVE means the request passed the configured checks, not that the transaction is safe.")


tab_eval, tab_bench, tab_audit = st.tabs(["Evaluate", "Benchmark", "Audit log"])

# ------------------------------------------------------------------ evaluate
with tab_eval:
    phase = st.radio("Phase", ["Phase 1 · Address injection", "Phase 2 · Mandates & behavior"],
                     horizontal=True)

    if phase.startswith("Phase 1"):
        labels = {f"{c.id} · [{c.category}] {c.title}": c.id for c in CASES}
        case = by_id(labels[st.selectbox("Scenario", list(labels))])
        st.markdown(f"**Expected label:** `{case.expected}`")
        base_req = case.request().model_dump(mode="json")

        left, right = st.columns(2)
        with left:
            st.subheader("User intent (trusted)")
            st.write(base_req["intent"]["instruction"])
            approved = st.text_area("Approved destinations (one per line)",
                                    "\n".join(base_req["intent"]["approved_destinations"]), key=f"ap-{case.id}")
            st.subheader("Policy (trusted)")
            st.json({k: base_req["policy"][k] for k in
                     ("agent_id", "max_amount_per_tx", "allowed_tokens", "allowed_chains", "vendor_registry",
                      "denylist")}, expanded=False)
        with right:
            st.subheader("Transaction the agent wants signed")
            tx = base_req["transaction"]
            to = st.text_input("to", tx["to"], key=f"to-{case.id}")
            c1, c2, c3 = st.columns(3)
            amount = c1.text_input("amount", tx["amount"], key=f"amt-{case.id}")
            token = c2.text_input("token", tx["token"], key=f"tok-{case.id}")
            chain = c3.text_input("chain", tx["chain"], key=f"ch-{case.id}")
            st.subheader("External context (untrusted)")
            ctx_edits = []
            for i, c in enumerate(base_req["context"]):
                st.markdown(f"`{c['id']}` · {c['source_type']}")
                content = st.text_area("content", c["content"], height=140, key=f"ctx-{case.id}-{i}")
                extracted = st.text_input("extracted address", c["extracted_address"] or "", key=f"ex-{case.id}-{i}")
                ctx_edits.append({**c, "content": content, "extracted_address": extracted or None})

        if st.button("Evaluate before signing", type="primary"):
            d = json.loads(json.dumps(base_req))
            d["intent"]["approved_destinations"] = [a.strip() for a in approved.splitlines() if a.strip()]
            d["transaction"].update({"to": to.strip(), "amount": amount, "token": token, "chain": chain})
            d["context"] = ctx_edits
            try:
                req = EvaluationRequest.model_validate(d)
            except Exception as e:
                st.error(f"Invalid request: {e}")
                st.stop()
            show_result(req, evaluate(req), case.expected)

    else:
        labels = {f"{c.id} · [{c.category}] {c.title}": c.id for c in CASES2}
        case = by_id2(labels[st.selectbox("Scenario", list(labels))])
        st.markdown(f"**Expected label:** `{case.expected}` · engine clock fixed at `{NOW:%Y-%m-%d %H:%M} UTC`")
        req0 = case.request()

        left, right = st.columns(2)
        with left:
            st.subheader("Signed mandate (from the principal)")
            if req0.mandate is None:
                st.error("No mandate attached. The request carries only an unsigned intent.")
            else:
                b = req0.mandate.body
                st.markdown(
                    f"**{b.mandate_id}** · {b.principal} → `{b.agent_id}`  \n"
                    f"{b.purpose}  \n"
                    f"Up to **{b.max_amount_per_tx} {b.token}** per payment · total "
                    f"**{b.max_total if b.max_total is not None else 'no cap'}** · "
                    f"max **{b.max_tx_count if b.max_tx_count is not None else 'unlimited'}** payments  \n"
                    f"Valid {b.valid_from:%Y-%m-%d} → {b.expires_at:%Y-%m-%d}")
                with st.expander("Raw mandate + signature"):
                    st.json(req0.mandate.model_dump(mode="json"))
            if req0.intent is not None:
                st.warning("Request also carries an unsigned intent (could be forged):")
                st.json(req0.intent.model_dump(mode="json"), expanded=False)

            st.subheader("Ledger history (engine's own records)")
            rows = case.ledger_rows()
            if rows:
                hist = pd.DataFrame([{
                    "when (UTC)": datetime.fromtimestamp(r["ts"], tz=timezone.utc).strftime("%m-%d %H:%M"),
                    "amount": str(r["amount"]), "to": r["dest"][:6] + "…" + r["dest"][-4:],
                    "mandate": r["mandate_id"]} for r in rows])
                st.dataframe(hist, hide_index=True, width="stretch", height=min(300, 38 + 35 * len(rows)))
            else:
                st.write("No prior payments.")

        with right:
            st.subheader("Payment the agent wants signed")
            tx = req0.transaction
            to = st.text_input("to", tx.to, key=f"p2to-{case.id}")
            amount = st.text_input("amount", str(tx.amount), key=f"p2amt-{case.id}")

        if st.button("Evaluate before signing", type="primary"):
            d = req0.model_dump(mode="json")
            d["transaction"].update({"to": to.strip(), "amount": amount})
            try:
                req = EvaluationRequest.model_validate(d)
            except Exception as e:
                st.error(f"Invalid request: {e}")
                st.stop()
            show_result(req, case.run(req), case.expected)

# ------------------------------------------------------------------ benchmark
with tab_bench:
    c1, c2 = st.columns(2)
    split = c1.radio("Split", ["all", "dev", "test"], horizontal=True)
    ph = c2.radio("Phase", ["all", "1", "2"], horizontal=True)
    m = run_metrics(None if split == "all" else split, None if ph == "all" else ph)
    k = st.columns(5)
    k[0].metric("Cases", m["n"])
    k[1].metric("Exact accuracy", f"{m['exact_decision_accuracy']:.0%}")
    k[2].metric("Detection rate", f"{m['detection_rate']:.0%}")
    k[3].metric("False positive rate", f"{m['false_positive_rate']:.0%}")
    k[4].metric("Latency p50", f"{m['latency_ms_p50']:.2f} ms")
    df = pd.DataFrame(m["rows"])[["phase", "id", "category", "split", "expected", "actual", "correct",
                                  "missing_codes", "title"]]
    st.dataframe(df, width="stretch", hide_index=True)
    st.warning("Synthetic cases written together with the engine. These numbers show rule coverage, "
               "not real-world performance. The test split is not an independent holdout.")

# ------------------------------------------------------------------ audit
with tab_audit:
    ok, bad = audit.verify_chain()
    (st.success if ok else st.error)(
        "Hash chain intact." if ok else f"Hash chain broken at record #{bad}: the log was modified.")
    rows = audit.rows()
    if rows:
        df = pd.DataFrame(rows)[["seq", "ts_utc", "request_id", "agent_id", "user_id", "decision", "risk_score",
                                 "reason_codes", "record_hash"]]
        st.dataframe(df, width="stretch", hide_index=True)
    else:
        st.write("No decisions recorded yet.")
