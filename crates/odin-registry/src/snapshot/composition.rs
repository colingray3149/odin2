//! Exclude live-read objects from composition identity so routine-only changes need no restart.

use std::fmt;

use serde::Serialize;

use super::contract::{Snapshot, SnapshotError};
use crate::schema::RegistryObject;

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
    objects: Vec<&'a RegistryObject>,
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

    /// Binary search and the borrowed index agree with a linear find,
    /// including a duplicate id where the first object wins.
    #[test]
    fn object_lookup_matches_a_linear_find() {
        let first = seat(SEAT);
        let mut second = seat(SEAT);
        second.relative_config = std::path::PathBuf::from("registry/seats/kubert/other.toml");
        let objects = vec![first, second, routine("weekly-review", ROUTINE)];
        let index = crate::snapshot::ObjectIndex::new(&objects);
        let found = index.get(RegistryKind::Seat, "kubert").expect("seat");
        assert_eq!(
            found.relative_config,
            std::path::PathBuf::from("registry/seats/kubert/seat.toml")
        );
        assert!(index.get(RegistryKind::Seat, "weekly-review").is_none());
        assert_eq!(
            index.enabled(RegistryKind::Seat, "kubert"),
            objects[0].enabled()
        );

        let snapshot = Snapshot::build(1, vec![seat(SEAT), routine("weekly-review", ROUTINE)])
            .expect("sorted snapshot");
        assert_eq!(
            snapshot
                .object(RegistryKind::Routine, "weekly-review")
                .map(|object| object.id.as_str()),
            Some("weekly-review")
        );
        assert!(snapshot
            .object(RegistryKind::Seat, "weekly-review")
            .is_none());
        assert_eq!(
            snapshot
                .object(RegistryKind::Seat, "kubert")
                .map(|object| object.id.as_str()),
            snapshot
                .objects
                .iter()
                .find(|object| object.kind() == RegistryKind::Seat && object.id == "kubert")
                .map(|object| object.id.as_str())
        );
    }
}
