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
