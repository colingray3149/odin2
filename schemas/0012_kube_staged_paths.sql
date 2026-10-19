-- Exact in-pod staging paths of one run's staged Job inputs, recorded by the
-- reconciler only after ArtifactStore::stage digest-verifies the bytes and
-- publishes the read-only ConfigMap. The carrier composition reads these
-- values verbatim — never a recomputed key or position — so a remote launch
-- binds the exact input path the API server mounted.
CREATE TABLE kube_job_staged_paths (
  run_id TEXT NOT NULL,
  artifact_ref TEXT NOT NULL,
  cluster TEXT NOT NULL,
  namespace TEXT NOT NULL,
  staged_path TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (run_id, artifact_ref)
) STRICT;
