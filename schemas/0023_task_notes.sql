-- Notes a seat pins to a task it can see open (a delegation, run or job id):
-- its live memory shows them while the task is open, and ops.history carries
-- them under the pinning session's project.
CREATE TABLE task_notes (
    task TEXT NOT NULL,
    seat TEXT NOT NULL,
    project TEXT,
    noted_at TEXT NOT NULL,
    note TEXT NOT NULL
) STRICT;

CREATE INDEX task_notes_task ON task_notes (task, noted_at);
