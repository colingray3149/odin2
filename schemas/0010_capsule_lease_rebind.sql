-- Capsule leases record the verified recency of their bound token, taken
-- from the token's signed claims (never parsed from the token id), so the
-- same seat and same session can atomically re-bind an OPEN lease to a
-- strictly newer verified authority under one durable journal event.
--
-- NULL means "issuance unknown" (every pre-migration lease). Unknown
-- issuance is never treated as older than the presenter: a differing token
-- is typed-refused until the identical bound token binds its exact signed
-- issuance (evidence repair, no rotation event), after which strict
-- recency governs. 0 is a valid known issuance (the epoch itself), not a
-- sentinel. The identical-token repair needs no clock-seam guarantee; the
-- verifier clock and the authority clock are separately injected, so no
-- watermark may be derived from them. Closed leases are never touched:
-- terminal state stays terminal.
ALTER TABLE capsule_lease
  ADD COLUMN token_issued_at_ms INTEGER
    DEFAULT NULL
    CHECK (token_issued_at_ms IS NULL OR token_issued_at_ms >= 0);
