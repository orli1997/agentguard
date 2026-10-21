-- AgentGuard analysis queries (SQLite).
-- Run after scripts/load_excel.py + scripts/run_batch.py.
-- Each query starts with "-- name: <sheet name>"; scripts/report.py exports each one to its own Excel sheet.


-- name: confusion_matrix
-- Rows = what should have happened (ground truth), columns = what the engine decided.
SELECT p.ground_truth                                   AS should_be,
       SUM(d.decision = 'APPROVE')                      AS engine_APPROVE,
       SUM(d.decision = 'REVIEW')                       AS engine_REVIEW,
       SUM(d.decision = 'BLOCK')                        AS engine_BLOCK,
       COUNT(*)                                         AS total
FROM payment_requests p
JOIN decisions d USING (request_id)
GROUP BY p.ground_truth
ORDER BY CASE p.ground_truth WHEN 'APPROVE' THEN 1 WHEN 'REVIEW' THEN 2 ELSE 3 END;


-- name: kpis
-- "Stopped" = REVIEW or BLOCK (the payment does not go out automatically).
WITH j AS (
    SELECT p.ground_truth AS t, d.decision AS e, d.latency_ms
    FROM payment_requests p JOIN decisions d USING (request_id)
)
SELECT COUNT(*)                                                                    AS requests,
       ROUND(100.0 * SUM(t = e) / COUNT(*), 1)                                     AS exact_match_pct,
       ROUND(100.0 * SUM(t <> 'APPROVE' AND e <> 'APPROVE')
                   / NULLIF(SUM(t <> 'APPROVE'), 0), 1)                            AS detection_rate_pct,
       ROUND(100.0 * SUM(t = 'APPROVE' AND e <> 'APPROVE')
                   / NULLIF(SUM(t = 'APPROVE'), 0), 1)                             AS false_positive_rate_pct,
       SUM(t <> 'APPROVE' AND e = 'APPROVE')                                       AS missed_should_stop,
       SUM(t = 'APPROVE' AND e <> 'APPROVE')                                       AS false_alarms,
       ROUND(AVG(latency_ms), 3)                                                   AS avg_latency_ms,
       ROUND(MAX(latency_ms), 3)                                                   AS max_latency_ms
FROM j;


-- name: by_scenario
SELECT p.scenario_type,
       COUNT(*)                                          AS requests,
       p.ground_truth                                    AS expected,
       SUM(d.decision = 'APPROVE')                       AS approved,
       SUM(d.decision = 'REVIEW')                        AS reviewed,
       SUM(d.decision = 'BLOCK')                         AS blocked,
       ROUND(100.0 * SUM(d.decision = p.ground_truth) / COUNT(*), 1) AS match_pct
FROM payment_requests p
JOIN decisions d USING (request_id)
GROUP BY p.scenario_type, p.ground_truth
ORDER BY match_pct, requests DESC;


-- name: disagreements
-- Every row where the engine and the label differ. Each one is either a missing rule or a wrong label.
SELECT p.request_id, p.ts, p.agent_id, p.mandate_id, p.payee_name, p.amount,
       p.scenario_type, p.ground_truth, d.decision, d.primary_reason, d.reason_codes, p.notes
FROM payment_requests p
JOIN decisions d USING (request_id)
WHERE d.decision <> p.ground_truth
ORDER BY p.ts;


-- name: reason_codes
-- How often each rule fired, and with what severity.
SELECT f.code, f.severity,
       COUNT(*)                         AS times_fired,
       COUNT(DISTINCT f.request_id)     AS requests
FROM decision_findings f
GROUP BY f.code, f.severity
ORDER BY CASE f.severity WHEN 'block' THEN 1 WHEN 'review' THEN 2 ELSE 3 END, times_fired DESC;


-- name: mandate_utilization
-- Budget used per mandate, from the engine's own ledger (approved payments only).
SELECT m.mandate_id, m.agent_id, m.payee_name,
       CAST(m.max_total AS REAL)                                       AS max_total,
       m.max_tx_count,
       COUNT(l.id)                                                     AS payments,
       ROUND(COALESCE(SUM(CAST(l.amount AS REAL)), 0), 2)              AS spent,
       CASE WHEN m.max_total IS NULL THEN NULL
            ELSE ROUND(100.0 * COALESCE(SUM(CAST(l.amount AS REAL)), 0) / CAST(m.max_total AS REAL), 1)
       END                                                             AS pct_of_budget,
       m.test_note
FROM mandates m
LEFT JOIN ledger l ON l.mandate_id = m.mandate_id
GROUP BY m.mandate_id
ORDER BY pct_of_budget DESC NULLS LAST;


-- name: suspicious_wallets
-- Destinations that received at least one blocked request. Unknown wallets first: an attacker-wallet profile.
-- Known vendors also appear (blocked for other reasons: wrong chain, expired mandate...), marked known_vendor.
SELECT p.to_address,
       COALESCE((SELECT v.vendor_name FROM vendors v WHERE v.address = p.to_address), '')  AS known_vendor,
       COUNT(*)                                            AS attempts,
       ROUND(SUM(p.amount), 2)                             AS attempted_usdc,
       COUNT(DISTINCT p.agent_id)                          AS agents_targeted,
       GROUP_CONCAT(DISTINCT p.scenario_type)              AS attack_types,
       MIN(p.ts)                                           AS first_seen,
       MAX(p.ts)                                           AS last_seen,
       CASE WHEN EXISTS (SELECT 1 FROM denylist x WHERE x.address = p.to_address)
            THEN 'yes' ELSE 'no' END                       AS on_denylist
FROM payment_requests p
JOIN decisions d USING (request_id)
WHERE d.decision = 'BLOCK'
GROUP BY p.to_address
ORDER BY known_vendor <> '', attempts DESC, attempted_usdc DESC;


-- name: daily_activity
SELECT DATE(p.ts)                                                    AS day,
       p.agent_id,
       COUNT(*)                                                      AS requests,
       SUM(d.decision = 'APPROVE')                                   AS approved,
       SUM(d.decision = 'REVIEW')                                    AS reviewed,
       SUM(d.decision = 'BLOCK')                                     AS blocked,
       ROUND(SUM(CASE WHEN d.decision = 'APPROVE' THEN p.amount ELSE 0 END), 2) AS approved_usdc,
       ROUND(SUM(CASE WHEN d.decision = 'BLOCK' THEN p.amount ELSE 0 END), 2)   AS blocked_usdc
FROM payment_requests p
JOIN decisions d USING (request_id)
GROUP BY day, p.agent_id
ORDER BY day, p.agent_id;


-- name: review_queue
-- What a human analyst would need to look at, worst first.
SELECT p.request_id, p.ts, p.agent_id, p.payee_name, p.to_address, p.amount,
       d.risk_score, d.primary_reason, f.message AS why
FROM payment_requests p
JOIN decisions d USING (request_id)
JOIN decision_findings f ON f.request_id = p.request_id AND f.seq = 0
WHERE d.decision = 'REVIEW'
ORDER BY d.risk_score DESC, p.ts;


-- name: blocked_value
-- Money the engine stopped, by attack type.
SELECT p.scenario_type,
       COUNT(*)                     AS blocked_requests,
       ROUND(SUM(p.amount), 2)      AS blocked_usdc
FROM payment_requests p
JOIN decisions d USING (request_id)
WHERE d.decision = 'BLOCK'
GROUP BY p.scenario_type
ORDER BY blocked_usdc DESC;


-- ======================================================================
-- Phase 3: reconciliation (run scripts/simulate_chain.py + scripts/reconcile_batch.py first)
-- ======================================================================


-- name: recon_summary
-- Every approval and every unexplained transfer, by outcome. observed_usdc counts successful transfers only.
WITH item_money AS (
    SELECT r.item_id, r.status, r.severity,
           COALESCE(CAST(a.amount AS REAL), 0)                                   AS approved,
           COALESCE((SELECT SUM(CAST(o.amount AS REAL)) FROM payment_observed o
                     WHERE o.status = 'success' AND instr(r.tx_hashes, o.tx_hash) > 0), 0) AS observed
    FROM recon_items r LEFT JOIN payment_approved a USING (request_id)
)
SELECT status, severity,
       COUNT(*)                         AS items,
       ROUND(SUM(approved), 2)          AS approved_usdc,
       ROUND(SUM(observed), 2)          AS observed_usdc,
       ROUND(SUM(observed - approved), 2) AS difference_usdc
FROM item_money
GROUP BY status, severity
ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
         items DESC;


-- name: recon_exceptions
-- The operations queue: everything that is not cleanly confirmed, worst first.
SELECT r.item_id, r.severity, r.status, r.request_id, p.agent_id, p.payee_name, p.amount AS approved_amount,
       r.match_method, r.explanation, r.action, r.handling
FROM recon_items r
LEFT JOIN payment_requests p USING (request_id)
WHERE r.status <> 'CONFIRMED'
ORDER BY CASE r.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
         r.request_id;


-- name: wallet_reconciliation
-- Per agent wallet: what AgentGuard approved vs. what actually left the wallet. Should net to zero.
WITH appr AS (
    SELECT from_wallet AS wallet, COUNT(*) AS approvals, SUM(CAST(amount AS REAL)) AS approved
    FROM payment_approved GROUP BY from_wallet
), outflow AS (
    SELECT from_address AS wallet, COUNT(*) AS transfers, SUM(CAST(amount AS REAL)) AS sent
    FROM payment_observed WHERE status = 'success' GROUP BY from_address
)
SELECT ag.agent_id, ag.wallet_address,
       COALESCE(appr.approvals, 0)                                  AS approvals,
       COALESCE(outflow.transfers, 0)                               AS transfers_out,
       ROUND(COALESCE(appr.approved, 0), 2)                         AS approved_usdc,
       ROUND(COALESCE(outflow.sent, 0), 2)                          AS sent_usdc,
       ROUND(COALESCE(outflow.sent, 0) - COALESCE(appr.approved, 0), 2) AS unexplained_usdc
FROM agents ag
LEFT JOIN appr ON appr.wallet = ag.wallet_address
LEFT JOIN outflow ON outflow.wallet = ag.wallet_address
ORDER BY ABS(unexplained_usdc) DESC;


-- name: recon_vs_labels
-- Reconciler output vs. the injected faults (synthetic data: shows rule coverage only).
SELECT l.expected_status,
       COALESCE(r.status, '(no item)')  AS reconciler_status,
       COUNT(*)                         AS items
FROM recon_labels l
LEFT JOIN recon_items r
       ON (l.subject = 'approval' AND r.request_id = l.ref)
       OR (l.subject = 'transfer' AND r.subject = 'transfer' AND r.tx_hashes = l.ref)
GROUP BY l.expected_status, reconciler_status
ORDER BY l.expected_status;


-- name: match_methods
-- How approvals were tied to on-chain transfers. Heuristic matches are weaker evidence.
SELECT match_method, status, COUNT(*) AS items
FROM recon_items WHERE subject = 'approval'
GROUP BY match_method, status
ORDER BY match_method, items DESC;
