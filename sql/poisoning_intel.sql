-- Analyst queries: what the address-poisoning intel changed (SQLite, over the service's audit_log).
-- Run:  python scripts/intel_queries.py [data/service.db]
-- Each query starts with "-- name: <name>".


-- name: intel_blocks
-- Every payment the intel stopped, with the evidence an analyst needs to open a case.
-- only_intel = 1 means no other rule would have blocked it: this is the value the intel adds.
SELECT a.ts_utc,
       a.request_id,
       a.agent_id,
       json_extract(a.request_json, '$.transaction.to')                  AS destination,
       json_extract(a.request_json, '$.transaction.amount')              AS amount,
       json_extract(a.request_json, '$.transaction.token')               AS token,
       json_extract(f.value, '$.evidence.mimics[0]')                     AS imitates,
       json_extract(f.value, '$.evidence.wallets_poisoned')              AS wallets_poisoned,
       json_extract(f.value, '$.evidence.losses_recorded')               AS losses_recorded,
       NOT EXISTS (SELECT 1 FROM json_each(a.result_json, '$.findings') g
                   WHERE json_extract(g.value, '$.severity') = 'block'
                     AND json_extract(g.value, '$.code') <> 'KNOWN_POISONING_ADDRESS') AS only_intel
FROM audit_log a, json_each(a.result_json, '$.findings') f
WHERE json_extract(f.value, '$.code') = 'KNOWN_POISONING_ADDRESS'
ORDER BY a.seq;


-- name: intel_value
-- Payments and value stopped by the intel, split by whether another rule would have caught them.
WITH b AS (
    SELECT a.seq,
           CAST(json_extract(a.request_json, '$.transaction.amount') AS REAL) AS amount,
           NOT EXISTS (SELECT 1 FROM json_each(a.result_json, '$.findings') g
                       WHERE json_extract(g.value, '$.severity') = 'block'
                         AND json_extract(g.value, '$.code') <> 'KNOWN_POISONING_ADDRESS') AS only_intel
    FROM audit_log a, json_each(a.result_json, '$.findings') f
    WHERE json_extract(f.value, '$.code') = 'KNOWN_POISONING_ADDRESS'
)
SELECT CASE only_intel WHEN 1 THEN 'only the intel' ELSE 'other rules too' END AS caught_by,
       COUNT(*)              AS payments,
       ROUND(SUM(amount), 6) AS value
FROM b GROUP BY only_intel;


-- name: review_queue_intel
-- Open REVIEW decisions with the intel status next to them, for triage.
-- A REVIEW where the intel was stale or unavailable deserves a second look: the attacker may be new.
SELECT a.ts_utc,
       a.request_id,
       json_extract(a.request_json, '$.transaction.to')     AS destination,
       json_extract(a.request_json, '$.transaction.amount') AS amount,
       a.reason_codes,
       COALESCE((SELECT group_concat(json_extract(g.value, '$.code'), ' ')
                 FROM json_each(a.result_json, '$.findings') g
                 WHERE json_extract(g.value, '$.code') LIKE 'POISONING_INTEL_%'
                    OR json_extract(g.value, '$.code') = 'POSSIBLE_POISONING_ADDRESS'),
                'NOT_CHECKED')                               AS intel_status
FROM audit_log a
WHERE a.decision = 'REVIEW'
ORDER BY a.seq;
