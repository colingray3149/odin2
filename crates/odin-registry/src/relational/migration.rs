use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;

use crate::RegistryFinding;

use super::context::RelationContext;
use super::paths::{relative_to_odin, sorted_paths};

/// Share migration version, path, and checksum with every database and sweep.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationRecord {
    pub version: i64,
    /// Repository-relative schema file, e.g. `schemas/0001_control_plane.sql`.
    pub path: &'static str,
    /// Independent expected BLAKE3; not derived from `canonical`.
    pub checksum: &'static str,
    canonical: &'static str,
}

impl MigrationRecord {
    pub fn checksum(&self) -> &'static str {
        self.checksum
    }

    pub fn file_name(&self) -> &'static str {
        self.path.rsplit('/').next().unwrap_or(self.path)
    }
}

/// Reject missing, extra, or changed schema files so registry validation agrees with embedded migrations.
pub const MIGRATION_REGISTRY: [MigrationRecord; 21] = [
    MigrationRecord {
        version: 1,
        path: "schemas/0001_control_plane.sql",
        checksum: "a53ed5f9fe76f07dda3c700eee4264b2aa494d63004dd0119cddd94dda3e0e70",
        canonical: include_str!("../../../../schemas/0001_control_plane.sql"),
    },
    MigrationRecord {
        version: 2,
        path: "schemas/0002_m1_ledger.sql",
        checksum: "9fe371da8045f7097c370c63b163c48db16fdce596f2b922e7f70461851b4484",
        canonical: include_str!("../../../../schemas/0002_m1_ledger.sql"),
    },
    MigrationRecord {
        version: 3,
        path: "schemas/0003_m1_compatibility.sql",
        checksum: "1fc13489cf4817447a379de92c1a5c51ca0f449d18a9ad952b4b7542b7ff074b",
        canonical: include_str!("../../../../schemas/0003_m1_compatibility.sql"),
    },
    MigrationRecord {
        version: 4,
        path: "schemas/0004_m85_authority.sql",
        checksum: "b854d8cb30f827f8baedf6ed8208fc7ef467370c32f97e1f0ee25d9314b03f9f",
        canonical: include_str!("../../../../schemas/0004_m85_authority.sql"),
    },
    MigrationRecord {
        version: 5,
        path: "schemas/0005_m85_worker.sql",
        checksum: "4fb45048268de69af221fbe9b782729900efa5deb73052e9e1c2ba099040e0d8",
        canonical: include_str!("../../../../schemas/0005_m85_worker.sql"),
    },
    MigrationRecord {
        version: 6,
        path: "schemas/0006_m85_policy_ledger.sql",
        checksum: "60eb8fea7db4e6830812f6a536d3ba56840c52b439af7926c38babea105907f8",
        canonical: include_str!("../../../../schemas/0006_m85_policy_ledger.sql"),
    },
    MigrationRecord {
        version: 7,
        path: "schemas/0007_m85_effect_receipts.sql",
        checksum: "be3ab3014d291fd3626aaeb630ac76c8ccae2e1ab98aa956622e6a0d6118d364",
        canonical: include_str!("../../../../schemas/0007_m85_effect_receipts.sql"),
    },
    MigrationRecord {
        version: 8,
        path: "schemas/0008_m9_jobs.sql",
        checksum: "bf804b564b3e54775fe20d25a4f4dd06a7206a5224c6cecd85a6c5535f2fa5a3",
        canonical: include_str!("../../../../schemas/0008_m9_jobs.sql"),
    },
    MigrationRecord {
        version: 9,
        path: "schemas/0009_m9_kube_operations.sql",
        checksum: "3a4ba2935d63f93a2ad87f7486e61d36039c8480d738302294875b5c9342ead3",
        canonical: include_str!("../../../../schemas/0009_m9_kube_operations.sql"),
    },
    MigrationRecord {
        version: 10,
        path: "schemas/0010_capsule_lease_rebind.sql",
        checksum: "c5ddc09d596beeeb5f2860b029ad5d693ba5b804bac26a22a6c25d5cde233306",
        canonical: include_str!("../../../../schemas/0010_capsule_lease_rebind.sql"),
    },
    MigrationRecord {
        version: 11,
        path: "schemas/0011_approval_feed.sql",
        checksum: "bf1100ef79a1276d5d1e56787b3e9685d0fb731ab88548cd55297eb283db4947",
        canonical: include_str!("../../../../schemas/0011_approval_feed.sql"),
    },
    MigrationRecord {
        version: 12,
        path: "schemas/0012_kube_staged_paths.sql",
        checksum: "78d0ce84546752d4a435dc47fb0aa20aa2a6dc3b32927731b19dd030db463b7e",
        canonical: include_str!("../../../../schemas/0012_kube_staged_paths.sql"),
    },
    MigrationRecord {
        version: 13,
        path: "schemas/0013_kube_operation_current.sql",
        checksum: "c5d2f13d4cef72cb08a229ea034c3f4bfcf5930d59464e4c25346a2338cc9119",
        canonical: include_str!("../../../../schemas/0013_kube_operation_current.sql"),
    },
    MigrationRecord {
        version: 14,
        path: "schemas/0014_terminal_service_units.sql",
        checksum: "802f156ef9e6183e74f95e802a63d49bd088fb6ee0577426045a44563e4aecf1",
        canonical: include_str!("../../../../schemas/0014_terminal_service_units.sql"),
    },
    MigrationRecord {
        version: 15,
        path: "schemas/0015_pod_workers.sql",
        checksum: "7afd2f0fb4503ecb4be7ec1bd53795e3cba878632404c8cef923585a929b0a9f",
        canonical: include_str!("../../../../schemas/0015_pod_workers.sql"),
    },
    MigrationRecord {
        version: 16,
        path: "schemas/0016_pod_secrets.sql",
        checksum: "00041d814b7f8b18e369af4b16462957c95f3b01ef77f45cec15ca8ee0110abb",
        canonical: include_str!("../../../../schemas/0016_pod_secrets.sql"),
    },
    MigrationRecord {
        version: 17,
        path: "schemas/0017_pod_retention.sql",
        checksum: "c9eb62919f075e3e194d6fb9283f6546f664d85b434cecb054ab3e8fadcd3002",
        canonical: include_str!("../../../../schemas/0017_pod_retention.sql"),
    },
    MigrationRecord {
        version: 18,
        path: "schemas/0018_approval_owner_decisions.sql",
        checksum: "ed13c7e60623a4c4eb6733f0aaffa7759181c4adfd10346a62a99e3020feee9b",
        canonical: include_str!("../../../../schemas/0018_approval_owner_decisions.sql"),
    },
    MigrationRecord {
        version: 19,
        path: "schemas/0019_host_command_bindings.sql",
        checksum: "7711296e8308d191d59229fc3bd4f962ad0985fd01e36d509d3798f11a78a951",
        canonical: include_str!("../../../../schemas/0019_host_command_bindings.sql"),
    },
    MigrationRecord {
        version: 20,
        path: "schemas/0020_trace.sql",
        checksum: "b51e9ec3d783009df1b9b6934bd7a540ec2b6b4c6a704540e66c3d898e9e1e74",
        canonical: include_str!("../../../../schemas/0020_trace.sql"),
    },
    MigrationRecord {
        version: 21,
        path: "schemas/0021_trace_call.sql",
        checksum: "c38575ea68f368d4b20b659c08d9887950604647e501889f1906c32821bf17af",
        canonical: include_str!("../../../../schemas/0021_trace_call.sql"),
    },
];

/// Production checks require complete, ordered migration files; fixture catalogs may be partial.
pub fn migration_inventory_findings(context: &RelationContext) -> Vec<RegistryFinding> {
    let mut findings = Vec::new();
    for (index, record) in MIGRATION_REGISTRY.iter().enumerate() {
        let expected = i64::try_from(index + 1).expect("registry length fits i64");
        if record.version != expected {
            findings.push(RegistryFinding::fail(
                "migration-registry-order",
                PathBuf::from(record.path),
                format!("registry position {index} must carry version {expected}"),
            ));
        }
        let relative = PathBuf::from(record.path);
        let absolute = context.odin_root.join(&relative);
        let metadata = match fs::symlink_metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error) => {
                findings.push(RegistryFinding::fail(
                    "migration-registry-missing",
                    relative,
                    format!("registered migration file is unavailable: {error}"),
                ));
                continue;
            }
        };
        if !metadata.is_file() {
            findings.push(RegistryFinding::fail(
                "migration-entry-type",
                relative,
                "registered migration must be a regular file",
            ));
            continue;
        }
        let bytes = match fs::read(&absolute) {
            Ok(bytes) => bytes,
            Err(error) => {
                findings.push(RegistryFinding::fail(
                    "migration-entry-read",
                    relative,
                    format!("could not read registered migration: {error}"),
                ));
                continue;
            }
        };
        let found = blake3::hash(&bytes).to_hex().to_string();
        let compiled = blake3::hash(record.canonical.as_bytes())
            .to_hex()
            .to_string();
        let expected = record.checksum();
        if found != expected || compiled != expected {
            findings.push(RegistryFinding::fail(
                "migration-checksum-drift",
                relative,
                format!(
                    "version {} expected checksum {expected}, found {found}",
                    record.version
                ),
            ));
        }
    }
    match sorted_paths(&context.schemas_root) {
        Ok(entries) => {
            for path in entries {
                let name = path.file_name().unwrap_or_default();
                if path.extension() != Some(OsStr::new("sql")) {
                    continue;
                }
                if !MIGRATION_REGISTRY
                    .iter()
                    .any(|record| name == OsStr::new(record.file_name()))
                {
                    findings.push(RegistryFinding::fail(
                        "migration-unregistered",
                        relative_to_odin(context, &path),
                        "unregistered schema-root SQL is not migration authority",
                    ));
                }
            }
        }
        Err(error) => findings.push(RegistryFinding::fail(
            "schema-root-read",
            PathBuf::from("schemas"),
            format!("could not inspect the schemas root: {error}"),
        )),
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_inventory_matches_the_registered_set() {
        let odin_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let findings = migration_inventory_findings(&RelationContext::new(&odin_root));
        assert!(
            findings.is_empty(),
            "committed migration inventory must audit cleanly: {findings:?}"
        );

        // A byte-exact fixture copy audits cleanly; any drift, gap, or
        // arbitrary root SQL fails with the named reason.
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "odin-registry-migration-inventory-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("schemas")).unwrap();
        for record in &MIGRATION_REGISTRY {
            std::fs::write(root.join(record.path), record.canonical).unwrap();
        }
        let context = RelationContext::new(&root);
        assert!(migration_inventory_findings(&context).is_empty());

        let drifted = root.join(MIGRATION_REGISTRY[1].path);
        let mut bytes = std::fs::read(&drifted).unwrap();
        bytes[0] ^= b'-';
        std::fs::write(&drifted, &bytes).unwrap();
        let findings = migration_inventory_findings(&context);
        assert!(findings.iter().any(|finding| {
            finding.code == "migration-checksum-drift" && finding.message.contains("version 2")
        }));
        std::fs::write(&drifted, MIGRATION_REGISTRY[1].canonical).unwrap();

        std::fs::remove_file(root.join(MIGRATION_REGISTRY[2].path)).unwrap();
        let findings = migration_inventory_findings(&context);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "migration-registry-missing"),
            "a missing registered migration must fail: {findings:?}"
        );

        std::fs::write(root.join("schemas/0009_arbitrary.sql"), "SELECT 1;").unwrap();
        let findings = migration_inventory_findings(&context);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "migration-unregistered"),
            "arbitrary root SQL must fail: {findings:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
