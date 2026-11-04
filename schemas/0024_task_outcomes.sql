-- Closed live entries are durable history records, not Brief summaries.
-- Project is part of the key: notes and outcomes never cross project scope.
CREATE TABLE task_outcomes (
    task TEXT NOT NULL,
    project TEXT NOT NULL,
    outcome TEXT NOT NULL,
    closed_at_ms INTEGER NOT NULL CHECK (closed_at_ms >= 0),
    history_recorded INTEGER NOT NULL DEFAULT 0 CHECK (history_recorded IN (0, 1)),
    PRIMARY KEY (task, project)
) STRICT;
