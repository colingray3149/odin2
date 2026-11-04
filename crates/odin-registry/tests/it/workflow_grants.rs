//! A workflow capability a pod profile grants must be one its seat may hold:
//! when the profile's seat is an operator seat, the capability's `seat_tags`
//! carry `operator` (or `*`). A lane adding a pod grant sees the missing tag.

use std::collections::BTreeMap;
use std::path::Path;

use odin_registry::schema::{CapabilityToml, SeatToml};
use odin_registry::{parse_objects, walk, ObjectConfig};

#[test]
fn pod_granted_workflows_carry_the_operator_seat_tag() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let parsed = parse_objects(&walk(root.join("registry")).objects);
    let mut capabilities: BTreeMap<&str, &CapabilityToml> = BTreeMap::new();
    let mut seats: BTreeMap<&str, &SeatToml> = BTreeMap::new();
    for object in &parsed.objects {
        match &object.config {
            ObjectConfig::Capability(capability) => {
                capabilities.insert(object.id.as_str(), capability);
            }
            ObjectConfig::Seat(seat) => {
                seats.insert(object.id.as_str(), seat);
            }
            _ => {}
        }
    }
    let mut missing = Vec::new();
    for object in &parsed.objects {
        let ObjectConfig::Workload(profile) = &object.config else {
            continue;
        };
        let seat = profile.seat.seat.as_str();
        let operator_seat = seats
            .get(seat)
            .is_some_and(|seat| seat.categories.contains("operator"));
        if !profile.enabled || !operator_seat {
            continue;
        }
        for tool in &profile.tools {
            let Some(capability) = capabilities.get(tool.as_str()) else {
                continue;
            };
            let tagged =
                capability.seat_tags.contains("operator") || capability.seat_tags.contains("*");
            if capability.is_workflow() && !tagged {
                missing.push(format!(
                    "workload {} grants workflow {tool} to operator seat {seat}; add \"operator\" \
                     to its seat_tags",
                    object.id
                ));
            }
        }
    }
    assert!(missing.is_empty(), "{missing:#?}");
}
