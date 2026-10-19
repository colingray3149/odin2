ALTER TABLE pod_worker_registry ADD COLUMN secret_name TEXT
  CHECK (secret_name IS NULL OR secret_name <> '');
ALTER TABLE pod_worker_registry ADD COLUMN secret_uid TEXT
  CHECK (secret_uid IS NULL OR (secret_uid <> '' AND secret_name IS NOT NULL));

CREATE UNIQUE INDEX pod_worker_active_secret
  ON pod_worker_registry (cluster, namespace, secret_name)
  WHERE state <> 'stopped' AND secret_name IS NOT NULL;

CREATE TRIGGER pod_worker_secret_release
BEFORE UPDATE OF state ON pod_worker_registry
WHEN NEW.state = 'released' AND NEW.secret_name IS NOT NULL AND NEW.secret_uid IS NULL
BEGIN
  SELECT RAISE(ABORT, 'pod release requires secret UID proof');
END;
