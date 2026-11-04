-- The newest wake of each stream of harness events about one job: the same
-- cause again inside the quiet window wakes nothing. `wake_id` names that
-- wake; `noted` is set once its repeats have been pinned to the job as a note.
CREATE TABLE quiet_wakes (
    job TEXT PRIMARY KEY NOT NULL,
    cause TEXT NOT NULL,
    wake_id TEXT NOT NULL,
    woke_ms INTEGER NOT NULL,
    noted INTEGER NOT NULL DEFAULT 0
) STRICT;
