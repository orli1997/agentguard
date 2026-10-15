"""Streamlit demo.  streamlit run app.py"""
from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from agentguard import ENGINE_VERSION, evaluate
from agentguard.audit import AuditLog
from agentguard.metrics import run as run_metrics
from agentguard.models import EvaluationRequest
from agentguard.scenarios import CASES, by_id

st.set_page_config(page_title="AgentGuard — Pre-Signing Risk Engine", layout="wide")
audit = AuditLog("agentguard_audit.db")

COLORS = {"APPROVE": "#1f7a3a", "REVIEW": "#b26b00", "BLOCK": "#b3261e"}
SEV_ICON = {"block": "⛔", "review": "⚠️", "info": "ℹ️"}

st.title("AgentGuard · Pre-Signing Risk Engine")
st.caption(f"Phase 1 · Scenario A: Payment Address Injection · engine {ENGINE_VERSION} · "
           "simulation only, no wallet, no real funds")

tab_eval, tab_bench, tab_audit = st.tabs(["Evaluate", "Benchmark", "Audit log"])

# ------------------------------------------------------------------ evaluate
with tab_eval:
    labels = {f"{c.id} · [{c.category}] {c.title}": c.id for c in CASES}
    choice = st.selectbox("Scenario", list(labels))
    case = by_id(labels[choice])
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
                 ("agent_id", "max_amount_per_tx", "allowed_tokens", "allowed_chains", "vendor_registry", "denylist")},
                expanded=False)
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
        res = evaluate(req)
        rec = audit.record(req, res)

        dec = res.decision.value
        st.markdown(
            f"<div style='padding:14px;border-radius:8px;background:{COLORS[dec]};color:white;"
            f"font-size:24px;font-weight:600'>{dec}"
            f"<span style='font-size:14px;font-weight:400;margin-left:16px'>"
            f"experimental risk score {res.risk_score}/100 · {res.latency_ms} ms</span></div>",
            unsafe_allow_html=True)
        if dec != case.expected:
            st.warning(f"Differs from the case label ({case.expected}) — expected if you edited inputs.")
        st.subheader("Findings")
        for f in res.findings:
            with st.expander(f"{SEV_ICON[f.severity.value]} {f.code} — {f.message}",
                             expanded=f.severity.value != "info"):
                st.json(f.evidence)
        st.caption(f"Audit record hash {rec['record_hash'][:16]}… (prev {rec['prev_hash'][:16]}…)")
        st.info("APPROVE means the request passed the configured checks — not that the transaction is safe.")

# ------------------------------------------------------------------ benchmark
with tab_bench:
    split = st.radio("Split", ["all", "dev", "test"], horizontal=True)
    m = run_metrics(None if split == "all" else split)
    k = st.columns(5)
    k[0].metric("Cases", m["n"])
    k[1].metric("Exact accuracy", f"{m['exact_decision_accuracy']:.0%}")
    k[2].metric("Detection rate", f"{m['detection_rate']:.0%}")
    k[3].metric("False positive rate", f"{m['false_positive_rate']:.0%}")
    k[4].metric("Latency p50", f"{m['latency_ms_p50']:.2f} ms")
    df = pd.DataFrame(m["rows"])[["id", "category", "split", "expected", "actual", "correct", "missing_codes", "title"]]
    st.dataframe(df, width="stretch", hide_index=True)
    st.warning("Synthetic cases written together with the engine. These numbers show rule coverage, "
               "not real-world performance. The test split is not an independent holdout.")

# ------------------------------------------------------------------ audit
with tab_audit:
    ok, bad = audit.verify_chain()
    (st.success if ok else st.error)(
        "Hash chain intact." if ok else f"Hash chain broken at record #{bad} — log was modified.")
    rows = audit.rows()
    if rows:
        df = pd.DataFrame(rows)[["seq", "ts_utc", "request_id", "agent_id", "decision", "risk_score",
                                 "reason_codes", "record_hash"]]
        st.dataframe(df, width="stretch", hide_index=True)
    else:
        st.write("No decisions recorded yet.")
