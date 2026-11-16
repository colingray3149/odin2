//! Read-only file roots exposed to seats on the serving host.

use std::collections::BTreeMap;
use std::path::PathBuf;

use odin_domain::huginn::FileRoot;
use odin_domain::SeatId;
use odin_registry::{ObjectConfig, RegistryObject};

pub(super) fn declared(
    registry: &[RegistryObject],
    file_roots: &[FileRoot],
    node: &str,
) -> BTreeMap<SeatId, Vec<PathBuf>> {
    let here = registry.iter().find_map(|object| match &object.config {
        ObjectConfig::Node(node_config) if object.id == node => Some(node_config.host.clone()),
        _ => None,
    });
    let mut seat_read_roots: BTreeMap<SeatId, Vec<PathBuf>> = BTreeMap::new();
    for root in file_roots
        .iter()
        .filter(|root| root.host.is_none() || root.host == here)
    {
        for seat in &root.allowed_seats {
            seat_read_roots
                .entry(seat.clone())
                .or_default()
                .push(root.canonical_path.clone());
        }
    }
    seat_read_roots
}
