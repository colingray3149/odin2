//! Exclude live-read objects from composition identity so routine-only changes need no restart.

use std::borrow::Cow;
use std::fmt;

use serde::Serialize;

use super::contract::{Snapshot, SnapshotError};
use crate::schema::{ObjectConfig, RegistryObject};

/// Exclude revision, tombstones, and live-read objects from the composition digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CompositionDigest([u8; 32]);

impl CompositionDigest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CompositionDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..8] {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct CompositionPayload<'a> {
    schema: &'static str,
    objects: Vec<Cow<'a, RegistryObject>>,
}

/// A capability's tests and probes only feed the Capabilities panel, so editing them keeps the composition.
fn without_evidence(object: &RegistryObject) -> Cow<'_, RegistryObject> {
    match &object.config {
        ObjectConfig::Capability(capability)
            if !(capability.tests.is_empty() && capability.probes.is_empty()) =>
        {
            let mut stripped = object.clone();
            if let ObjectConfig::Capability(stripped) = &mut stripped.config {
                stripped.tests.clear();
                stripped.probes.clear();
            }
            Cow::Owned(stripped)
        }
        _ => Cow::Borrowed(object),
    }
}

const COMPOSITION_SCHEMA: &str = "odin.registry-composition.v1";

impl Snapshot {
    pub fn composition_digest(&self) -> Result<CompositionDigest, SnapshotError> {
        let payload = CompositionPayload {
            schema: COMPOSITION_SCHEMA,
            objects: self
                .objects
                .iter()
                .filter(|object| !object.kind().is_read_live())
                .map(without_evidence)
                .collect(),
        };
        let bytes = serde_json::to_vec(&payload)?;
        Ok(CompositionDigest(*blake3::hash(&bytes).as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use crate::schema::{parse_object_toml, RegistryKind, RegistryObject};
    use crate::snapshot::Snapshot;

    const SEAT: &str = include_str!("../../../../registry/seats/kubert/seat.toml");
    const ROUTINE: &str = include_str!("../../../../registry/routines/weekly-review/routine.toml");

    fn seat(source: &str) -> RegistryObject {
        parse_object_toml(
            RegistryKind::Seat,
            "kubert",
            "registry/seats/kubert/seat.toml",
            source,
        )
        .expect("seat parses")
    }

    fn routine(id: &str, source: &str) -> RegistryObject {
        parse_object_toml(
            RegistryKind::Routine,
            id,
            format!("registry/routines/{id}/routine.toml"),
            source,
        )
        .expect("routine parses")
    }

    fn digest(revision: u64, objects: Vec<RegistryObject>) -> super::CompositionDigest {
        Snapshot::build(revision, objects)
            .expect("snapshot")
            .composition_digest()
            .expect("digest")
    }

    /// Routine additions, edits, and removals do not change the composition digest.
    #[test]
    fn a_routine_publication_keeps_the_composition() {
        let base = digest(7, vec![seat(SEAT)]);
        assert_eq!(
            base,
            digest(8, vec![seat(SEAT), routine("weekly-review", ROUTINE)])
        );
        let edited = ROUTINE.replace("sun 18:00", "sat 09:00");
        assert_eq!(
            base,
            digest(9, vec![seat(SEAT), routine("weekly-review", &edited)])
        );
        assert_eq!(base, digest(10, vec![seat(SEAT)]));
    }

    #[test]
    fn a_seat_change_is_a_new_composition() {
        let changed = SEAT.replacen("description = \"", "description = \"Changed. ", 1);
        assert_ne!(changed, SEAT, "the fixture edit applies");
        assert_ne!(digest(7, vec![seat(SEAT)]), digest(8, vec![seat(&changed)]));
    }
}
