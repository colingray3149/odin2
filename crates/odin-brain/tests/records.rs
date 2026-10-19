//! The curated brain records path a seat's `brain` tool reads: rows as
//! `brain-load` writes them, served by search and by id, with local_only
//! and secret-bearing records withheld from a cloud lane.

use odin_brain::index::postgres::{BrainPostgres, RecordFilters, RecordRead};

#[path = "support/postgres.rs"]
mod postgres_cluster;

fn psql(conninfo: &str, sql: &str) {
    let output = std::process::Command::new("psql")
        .args([conninfo, "-X", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

const ROWS: &str = "
INSERT INTO brain_person VALUES ('maya-1', 'Maya', '{\"names\": [\"Maya\"], \"handles\": [{\"source\": \"snapchat\", \"handle\": \"maya.k\"}]}',
  NULL, '2024-05-01', 'odin-brain/records/Local/people/maya-1.json', false, to_tsvector('simple', 'Maya maya.k'));
INSERT INTO brain_person_handle VALUES ('maya-1', 'handle', 'snapchat', 'maya.k'), ('maya-1', 'name', '', 'Maya');
INSERT INTO brain_unit VALUES ('snapchat/u1', 'snapchat', 'h1', 'Maya and Colin plan a Japan trip.', ARRAY['travel'],
  '[{\"name\": \"Maya\", \"handle\": \"maya.k\"}]', '2024-04-30', '2024-05-01', 'odin-brain/records/Local/proposals/snapchat/u1.json',
  false, NULL, array_fill(0.1, ARRAY[256])::halfvec(256), to_tsvector('english', 'Maya and Colin plan a Japan trip. travel Maya maya.k'));
INSERT INTO brain_fact (fact_id, unit_id, subject, text, when_text, valid_from, local_only, embedding, tsv)
  VALUES ('snapchat/u1#0', 'snapchat/u1', 'Maya', 'Maya wants to visit Japan in June', '2024-05', '2024-05-01', false,
  array_fill(0.1, ARRAY[256])::halfvec(256), to_tsvector('english', 'Maya wants to visit Japan in June'));
INSERT INTO brain_fact_evidence VALUES ('snapchat/u1#0', 'm1', '2024-05-01', 'Maya', 'Tokyo in June?');
INSERT INTO brain_unit VALUES ('discord/u2', 'discord', 'h2', 'Private plans about Japan.', ARRAY[]::text[], '[]',
  NULL, NULL, 'odin-brain/records/Local/proposals/discord/u2.json', true, NULL, NULL, to_tsvector('english', 'Private plans about Japan.'));
INSERT INTO brain_fact (fact_id, unit_id, subject, text, when_text, local_only, tsv)
  VALUES ('discord/u2#0', 'discord/u2', 'Colin', 'Colin booked Japan flights', '', true, to_tsvector('english', 'Colin booked Japan flights'));
INSERT INTO brain_unit VALUES ('discord/u3', 'discord', 'h3', 'Card details.', ARRAY[]::text[], '[]',
  NULL, NULL, 'odin-brain/records/Local/proposals/discord/u3.json', false, 'payment-card', NULL, to_tsvector('english', 'Card details Japan'));
INSERT INTO brain_fact (fact_id, unit_id, subject, text, when_text, local_only, tsv)
  VALUES ('discord/u3#0', 'discord/u3', 'Colin', 'card number', '', false, to_tsvector('english', 'card number'));
INSERT INTO brain_asset VALUES ('google-takeout/Google Photos/Trip/tokyo.jpg', 'photo', 'a', '2024-06-03', '{\"lat\": 35.68, \"lon\": 139.76}',
  'Trip', 100, false, to_tsvector('simple', 'google takeout Google Photos Trip tokyo jpg Trip'));
INSERT INTO brain_asset VALUES ('Private/family.jpg', 'photo', 'b', NULL, NULL, 'Private', 100, true, to_tsvector('simple', 'Private family jpg'));
";

#[test]
fn a_cloud_lane_reads_ordinary_records_with_evidence_and_is_refused_the_rest() {
    let cluster = postgres_cluster::TestCluster::start();
    let store = BrainPostgres::connect(&cluster.conninfo).unwrap();
    psql(&cluster.conninfo, ROWS);

    // Hybrid search: the ordinary unit and fact rank, the fact with its
    // evidence line; local_only and secret rows only show as withheld.
    let found = store
        .search_records(
            "when did Maya and I talk about Japan",
            Some(vec![0.1; 2048]),
            &RecordFilters::default(),
            false,
            10,
        )
        .unwrap();
    let ids: Vec<&str> = found
        .hits
        .iter()
        .map(|hit| hit["id"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains(&"snapchat/u1") && ids.contains(&"snapchat/u1#0"),
        "{ids:?}"
    );
    assert!(!ids.iter().any(|id| id.starts_with("discord/")), "{ids:?}");
    assert!(found.withheld);
    let fact = found
        .hits
        .iter()
        .find(|hit| hit["id"] == "snapchat/u1#0")
        .unwrap();
    assert_eq!(fact["evidence"][0]["text"], "Tokyo in June?");

    // A person by their Snapchat handle, with the conversations naming them.
    let RecordRead::Found(person) = store.read_person("@maya.k", false).unwrap() else {
        panic!("person by handle");
    };
    assert_eq!(person["name"], "Maya");
    assert_eq!(person["units"][0]["id"], "snapchat/u1");

    // Reads by id name why a record is withheld.
    let RecordRead::Withheld(reason) = store.read_fact("discord/u2#0", false).unwrap() else {
        panic!("local_only fact served to a cloud lane");
    };
    assert!(reason.contains("local_only"), "{reason}");
    let RecordRead::Withheld(reason) = store.read_fact("discord/u3#0", true).unwrap() else {
        panic!("secret-bearing fact served");
    };
    assert!(reason.contains("payment-card"), "{reason}");
    assert!(matches!(
        store.read_fact("discord/u2#0", true).unwrap(),
        RecordRead::Found(_)
    ));

    // Photos: index metadata by place and date; a private photo is refused.
    let filters = RecordFilters {
        from: Some("2024-06-01".into()),
        ..RecordFilters::default()
    };
    let photos = store
        .find_assets("", &filters, Some((35.7, 139.7, 20.0)), false, 10)
        .unwrap();
    assert_eq!(photos.hits.len(), 1);
    assert_eq!(photos.hits[0]["album"], "Trip");
    assert!(matches!(
        store.read_asset("Private/family.jpg", false).unwrap(),
        RecordRead::Withheld(_)
    ));
}

#[test]
fn a_rare_query_word_outranks_a_common_one() {
    let cluster = postgres_cluster::TestCluster::start();
    let store = BrainPostgres::connect(&cluster.conninfo).unwrap();
    psql(&cluster.conninfo, ROWS);
    // Many facts name Maya; one also names Japan. Asking about both must
    // surface the Japan fact first, not the Maya facts that repeat the
    // common word.
    psql(
        &cluster.conninfo,
        "INSERT INTO brain_fact (fact_id, unit_id, subject, text, when_text, local_only, tsv)
         SELECT 'snapchat/u1#' || n, 'snapchat/u1', 'Maya', 'Maya likes games ' || n, '', false,
                to_tsvector('english', 'Maya Maya likes games')
         FROM generate_series(1, 60) n",
    );
    let found = store
        .search_records(
            "when did Maya and I last talk about Japan",
            None,
            &RecordFilters::default(),
            false,
            3,
        )
        .unwrap();
    let ids: Vec<&str> = found
        .hits
        .iter()
        .map(|hit| hit["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"snapchat/u1#0"), "{ids:?}");
}
