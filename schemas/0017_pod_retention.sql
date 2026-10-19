ALTER TABLE pod_worker_registry ADD COLUMN retained_workspace INTEGER NOT NULL DEFAULT 0 CHECK(retained_workspace IN (0,1));
ALTER TABLE pod_worker_registry ADD COLUMN release_attempted INTEGER NOT NULL DEFAULT 0 CHECK(release_attempted IN (0,1));
ALTER TABLE pod_worker_registry ADD COLUMN stop_admitted INTEGER NOT NULL DEFAULT 0 CHECK(stop_admitted IN (0,1));

-- Existing Secret-bearing workers are Claude carriers. Their historical gate
-- release may have succeeded without the ledger acknowledgement: retain them.
UPDATE pod_worker_registry SET retained_workspace=1, release_attempted=1 WHERE secret_name IS NOT NULL;
