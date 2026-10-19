-- M11 adds the approval feed's partial sequence index. Every approval-feed
-- page read (sequence > cursor AND kind LIKE 'approval.%' ORDER BY sequence
-- LIMIT n) and the feed head probe must touch only `approval.*` events and
-- never scan the whole journal; the partial-index predicate matches the feed
-- queries' predicate exactly so the planner can prove applicability.
CREATE INDEX IF NOT EXISTS events_approval_feed_idx
  ON events(sequence) WHERE kind LIKE 'approval.%';
