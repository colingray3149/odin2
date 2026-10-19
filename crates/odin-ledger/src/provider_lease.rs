//! Immutable provider bindings with explicit boundary rotation.

use std::str::FromStr;

use odin_domain::{LaneId, LeaseId, ProviderId};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::{decode_utc, encode_utc, Ledger, LedgerError, LedgerResult};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderLeaseBoundary {
    LaneStart,
    Turn,
    Attempt,
    Run,
    Quota,
    Operator,
}

#[derive(Clone, Debug)]
pub struct NewProviderLease {
    pub lease_id: LeaseId,
    pub lane_id: LaneId,
    pub provider_id: ProviderId,
    pub account_handle: String,
    pub model: String,
    pub role: String,
    pub affinity_key: String,
    pub quota_snapshot: Value,
    pub selection_reason: String,
    pub started_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderLeaseEnd {
    pub boundary: ProviderLeaseBoundary,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProviderLease {
    pub lease_id: LeaseId,
    pub lane_id: LaneId,
    pub provider_id: ProviderId,
    pub account_handle: String,
    pub model: String,
    pub role: String,
    pub affinity_key: String,
    pub quota_snapshot: Value,
    pub selection_reason: String,
    pub predecessor_id: Option<LeaseId>,
    pub revision: i64,
    pub started_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub ended_at: Option<OffsetDateTime>,
    pub end: Option<ProviderLeaseEnd>,
    pub started_logical: u64,
    pub ended_logical: Option<u64>,
}

impl Ledger {
    /// Starts a binding only when the lane has no unended provider lease.
    ///
    /// The database's partial unique index is the final arbiter, avoiding an
    /// exists-then-insert race between multiple ledger connections.
    pub fn start_provider_lease(&self, lease: NewProviderLease) -> LedgerResult<ProviderLease> {
        let lease_id = lease.lease_id.clone();
        insert_provider_lease(self.connection(), lease, None)?;
        self.provider_lease_by_id(&lease_id)?.ok_or_else(|| {
            LedgerError::invalid_data(format!(
                "provider lease {lease_id} insert completed without a readable row"
            ))
        })
    }

    pub fn provider_lease_by_id(&self, lease_id: &LeaseId) -> LedgerResult<Option<ProviderLease>> {
        let row = self
            .connection()
            .query_row(
                PROVIDER_LEASE_SELECT_WITH_ID,
                [lease_id.to_string()],
                provider_lease_row,
            )
            .optional()?;
        row.map(decode_provider_lease).transpose()
    }

    pub fn active_provider_lease_for_lane(
        &self,
        lane_id: &LaneId,
    ) -> LedgerResult<Option<ProviderLease>> {
        let row = self
            .connection()
            .query_row(
                PROVIDER_LEASE_SELECT_WITH_LANE,
                [lane_id.to_string()],
                provider_lease_row,
            )
            .optional()?;
        row.map(decode_provider_lease).transpose()
    }

    /// Lists every unended provider lease across all lanes.
    ///
    /// Read-only: rows are returned lane-by-lane in start order so callers can
    /// render fleet-wide provider status without mutating bindings.
    pub fn active_provider_leases(&self) -> LedgerResult<Vec<ProviderLease>> {
        let mut statement = self
            .connection()
            .prepare(PROVIDER_LEASE_SELECT_ACTIVE_ALL)?;
        let rows = statement
            .query_map([], provider_lease_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().map(decode_provider_lease).collect()
    }

    /// Lists a lane's complete provider lease lineage, oldest first.
    ///
    /// Read-only history: ended predecessor rows stay untouched so lineage and
    /// end reasons remain auditable after rotation.
    pub fn provider_leases_for_lane(&self, lane_id: &LaneId) -> LedgerResult<Vec<ProviderLease>> {
        let mut statement = self.connection().prepare(PROVIDER_LEASE_SELECT_FOR_LANE)?;
        let rows = statement
            .query_map([lane_id.to_string()], provider_lease_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().map(decode_provider_lease).collect()
    }

    /// Lists every lane that owns at least one provider lease, sorted.
    pub fn provider_lease_lanes(&self) -> LedgerResult<Vec<LaneId>> {
        let mut statement = self
            .connection()
            .prepare("SELECT DISTINCT lane_id FROM provider_leases ORDER BY lane_id")?;
        let lanes = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        lanes
            .iter()
            .map(|lane| parse_id("lane", lane, LaneId::from_str))
            .collect()
    }

    /// Ends the predecessor and creates its successor in one transaction.
    ///
    /// Provider/account/model fields are never updated in place: any binding change is represented
    /// by a successor row and can therefore happen only at this explicitly typed boundary.
    pub fn rotate_provider_lease_at_boundary(
        &mut self,
        predecessor_id: &LeaseId,
        expected_revision: i64,
        ended_at: OffsetDateTime,
        end: ProviderLeaseEnd,
        successor: NewProviderLease,
    ) -> LedgerResult<ProviderLease> {
        let predecessor_id = predecessor_id.clone();
        self.with_tx(|transaction| {
            let predecessor = provider_lease_in_transaction(transaction, &predecessor_id)?;
            if predecessor.lane_id != successor.lane_id {
                return Err(LedgerError::invalid_data(format!(
                    "provider successor {} changes lane {} to {}",
                    successor.lease_id, predecessor.lane_id, successor.lane_id
                )));
            }
            // Wall timestamps are presentation only. The SQL CAS below owns
            // successor chronology through the predecessor's logical boundary.

            end_provider_lease(
                transaction,
                &predecessor_id,
                expected_revision,
                ended_at,
                &end,
            )?;
            let successor_id = successor.lease_id.clone();
            insert_provider_lease(transaction, successor, Some(&predecessor_id))?;
            provider_lease_in_transaction(transaction, &successor_id)
        })
    }
}

fn insert_provider_lease(
    connection: &Connection,
    lease: NewProviderLease,
    predecessor_id: Option<&LeaseId>,
) -> LedgerResult<()> {
    let started_logical: i64 = match predecessor_id {
        Some(predecessor) => connection.query_row(
            "SELECT ended_logical FROM provider_leases
             WHERE provider_lease_id=?1 AND ended_at IS NOT NULL AND ended_logical IS NOT NULL",
            [predecessor.to_string()],
            |row| row.get(0),
        )?,
        None => connection.query_row(
            "SELECT COALESCE((
                SELECT ended_logical FROM provider_leases
                WHERE lane_id=?1 AND ended_logical IS NOT NULL
                ORDER BY ended_logical DESC, provider_lease_id DESC LIMIT 1
             ),0)",
            [lease.lane_id.to_string()],
            |row| row.get(0),
        )?,
    };
    connection.execute(
        "INSERT INTO provider_leases (
             provider_lease_id, lane_id, provider_id, account_handle, model, role,
             affinity_key, quota_snapshot_json, selection_reason, predecessor_id,
             revision, started_at, expires_at, started_logical, expires_logical
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, ?11, ?12, ?13, NULL)",
        params![
            lease.lease_id.to_string(),
            lease.lane_id.to_string(),
            lease.provider_id.to_string(),
            lease.account_handle,
            lease.model,
            lease.role,
            lease.affinity_key,
            serde_json::to_string(&lease.quota_snapshot)?,
            lease.selection_reason,
            predecessor_id.map(ToString::to_string),
            encode_utc(lease.started_at)?,
            lease.expires_at.map(encode_utc).transpose()?,
            started_logical,
        ],
    )?;
    Ok(())
}

fn end_provider_lease(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
    expected_revision: i64,
    ended_at: OffsetDateTime,
    end: &ProviderLeaseEnd,
) -> LedgerResult<()> {
    let changed = transaction.execute(
        "UPDATE provider_leases
         SET ended_at = ?1, end_reason = ?2,
             ended_logical = started_logical + 1, revision = revision + 1
         WHERE provider_lease_id = ?3 AND revision = ?4 AND ended_at IS NULL
           AND ended_logical IS NULL",
        params![
            encode_utc(ended_at)?,
            serde_json::to_string(end)?,
            lease_id.to_string(),
            expected_revision,
        ],
    )?;
    if changed != 0 {
        return Ok(());
    }

    let state = transaction
        .query_row(
            "SELECT revision, ended_at FROM provider_leases WHERE provider_lease_id = ?1",
            [lease_id.to_string()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .optional()?
        .ok_or_else(|| LedgerError::invalid_data(format!("unknown provider lease {lease_id}")))?;
    if state.0 != expected_revision {
        return Err(LedgerError::StaleActor {
            actor: format!("provider-lease:{lease_id}"),
            expected_revision,
            actual_revision: state.0,
        });
    }
    Err(LedgerError::invalid_data(format!(
        "provider lease {lease_id} already ended at {}",
        state.1.as_deref().unwrap_or("<invalid>")
    )))
}

fn provider_lease_in_transaction(
    transaction: &Transaction<'_>,
    lease_id: &LeaseId,
) -> LedgerResult<ProviderLease> {
    let row = transaction.query_row(
        PROVIDER_LEASE_SELECT_WITH_ID,
        [lease_id.to_string()],
        provider_lease_row,
    )?;
    decode_provider_lease(row)
}

const PROVIDER_LEASE_SELECT_WITH_ID: &str = "SELECT provider_lease_id, lane_id, provider_id, account_handle, model, role, affinity_key, quota_snapshot_json, selection_reason, predecessor_id, revision, started_at, expires_at, ended_at, end_reason, started_logical, ended_logical FROM provider_leases WHERE provider_lease_id = ?1";

const PROVIDER_LEASE_SELECT_WITH_LANE: &str = "SELECT provider_lease_id, lane_id, provider_id, account_handle, model, role, affinity_key, quota_snapshot_json, selection_reason, predecessor_id, revision, started_at, expires_at, ended_at, end_reason, started_logical, ended_logical FROM provider_leases WHERE lane_id = ?1 AND ended_at IS NULL ORDER BY started_logical DESC, provider_lease_id DESC LIMIT 1";

const PROVIDER_LEASE_SELECT_ACTIVE_ALL: &str = "SELECT provider_lease_id, lane_id, provider_id, account_handle, model, role, affinity_key, quota_snapshot_json, selection_reason, predecessor_id, revision, started_at, expires_at, ended_at, end_reason, started_logical, ended_logical FROM provider_leases WHERE ended_at IS NULL ORDER BY lane_id, started_logical, provider_lease_id";

const PROVIDER_LEASE_SELECT_FOR_LANE: &str = "SELECT provider_lease_id, lane_id, provider_id, account_handle, model, role, affinity_key, quota_snapshot_json, selection_reason, predecessor_id, revision, started_at, expires_at, ended_at, end_reason, started_logical, ended_logical FROM provider_leases WHERE lane_id = ?1 ORDER BY started_logical, provider_lease_id";

type ProviderLeaseRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    i64,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    Option<i64>,
);

fn provider_lease_row(row: &Row<'_>) -> rusqlite::Result<ProviderLeaseRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
    ))
}

fn decode_provider_lease(row: ProviderLeaseRow) -> LedgerResult<ProviderLease> {
    let (
        lease_id,
        lane_id,
        provider_id,
        account_handle,
        model,
        role,
        affinity_key,
        quota_snapshot,
        selection_reason,
        predecessor_id,
        revision,
        started_at,
        expires_at,
        ended_at,
        end,
        started_logical,
        ended_logical,
    ) = row;
    Ok(ProviderLease {
        lease_id: parse_id("provider lease", &lease_id, LeaseId::from_str)?,
        lane_id: parse_id("lane", &lane_id, LaneId::from_str)?,
        provider_id: parse_id("provider", &provider_id, ProviderId::from_str)?,
        account_handle,
        model,
        role,
        affinity_key,
        quota_snapshot: serde_json::from_str(&quota_snapshot)?,
        selection_reason,
        predecessor_id: predecessor_id
            .as_deref()
            .map(|value| parse_id("provider predecessor", value, LeaseId::from_str))
            .transpose()?,
        revision,
        started_at: decode_utc(&started_at)?,
        expires_at: expires_at.as_deref().map(decode_utc).transpose()?,
        ended_at: ended_at.as_deref().map(decode_utc).transpose()?,
        end: end.as_deref().map(serde_json::from_str).transpose()?,
        started_logical: u64::try_from(started_logical).map_err(|error| {
            LedgerError::invalid_data_caused_by("provider lease has negative logical start", error)
        })?,
        ended_logical: ended_logical
            .map(|value| {
                u64::try_from(value).map_err(|error| {
                    LedgerError::invalid_data_caused_by(
                        "provider lease has negative logical boundary",
                        error,
                    )
                })
            })
            .transpose()?,
    })
}

fn parse_id<T, E>(
    kind: &str,
    value: &str,
    parser: impl FnOnce(&str) -> Result<T, E>,
) -> LedgerResult<T>
where
    E: std::error::Error + Send + Sync + 'static,
{
    parser(value).map_err(|error| {
        LedgerError::invalid_data_caused_by(format!("invalid {kind} identifier {value:?}"), error)
    })
}

#[cfg(test)]
mod tests {
    use odin_domain::{LaneId, LeaseId, ProviderId};
    use serde_json::json;
    use time::OffsetDateTime;

    use super::{NewProviderLease, ProviderLeaseBoundary, ProviderLeaseEnd};
    use crate::Ledger;

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(seconds).unwrap()
    }

    fn seed_lane(ledger: &Ledger, lane_id: &LaneId) {
        ledger
            .connection()
            .execute(
                "INSERT INTO lanes (
                     lane_id, seat_id, template_id, backend, status, created_by, created_at, updated_at
                 ) VALUES (?1, 'seat-a', 'template-a', 'local_omp', 'ready', 'test', ?2, ?2)",
                rusqlite::params![lane_id.to_string(), crate::encode_utc(at(1)).unwrap()],
            )
            .unwrap();
    }

    fn lease(id: &str, lane_id: LaneId, provider: &str, started_at: i64) -> NewProviderLease {
        NewProviderLease {
            lease_id: LeaseId::new(id).unwrap(),
            lane_id,
            provider_id: ProviderId::new(provider).unwrap(),
            account_handle: format!("{provider}-account"),
            model: format!("{provider}-model"),
            role: "primary".to_owned(),
            affinity_key: "project-a".to_owned(),
            quota_snapshot: json!({"remaining": 1}),
            selection_reason: "policy".to_owned(),
            started_at: at(started_at),
            expires_at: None,
        }
    }

    #[test]
    fn provider_binding_changes_only_by_boundary_successor() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let lane_id = LaneId::new("lane-a").unwrap();
        seed_lane(&ledger, &lane_id);
        let first = ledger
            .start_provider_lease(lease("lease-a", lane_id.clone(), "provider-a", 10))
            .unwrap();

        assert!(ledger
            .start_provider_lease(lease("lease-illegal", lane_id.clone(), "provider-b", 11))
            .is_err());
        assert_eq!(
            ledger
                .active_provider_lease_for_lane(&lane_id)
                .unwrap()
                .unwrap()
                .provider_id,
            ProviderId::new("provider-a").unwrap()
        );

        let second = ledger
            .rotate_provider_lease_at_boundary(
                &first.lease_id,
                first.revision,
                at(20),
                ProviderLeaseEnd {
                    boundary: ProviderLeaseBoundary::Turn,
                    reason: "quota boundary".to_owned(),
                },
                lease("lease-b", lane_id.clone(), "provider-b", 20),
            )
            .unwrap();
        assert_eq!(second.predecessor_id, Some(first.lease_id));
        assert_eq!(
            ledger
                .active_provider_lease_for_lane(&lane_id)
                .unwrap()
                .unwrap()
                .lease_id,
            second.lease_id
        );
    }

    #[test]
    fn provider_lease_reads_list_active_lanes_and_lineage() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let lane_a = LaneId::new("lane-a").unwrap();
        let lane_b = LaneId::new("lane-b").unwrap();
        seed_lane(&ledger, &lane_a);
        seed_lane(&ledger, &lane_b);
        let first = ledger
            .start_provider_lease(lease("lease-a", lane_a.clone(), "provider-a", 10))
            .unwrap();
        let second = ledger
            .rotate_provider_lease_at_boundary(
                &first.lease_id,
                first.revision,
                at(20),
                ProviderLeaseEnd {
                    boundary: ProviderLeaseBoundary::Quota,
                    reason: "quota boundary".to_owned(),
                },
                lease("lease-b", lane_a.clone(), "provider-b", 20),
            )
            .unwrap();
        let third = ledger
            .start_provider_lease(lease("lease-c", lane_b.clone(), "provider-c", 15))
            .unwrap();

        let active = ledger.active_provider_leases().unwrap();
        let active_ids: Vec<_> = active.iter().map(|item| item.lease_id.clone()).collect();
        assert_eq!(active_ids, [second.lease_id.clone(), third.lease_id]);
        assert!(active.iter().all(|item| item.ended_at.is_none()));

        let lineage = ledger.provider_leases_for_lane(&lane_a).unwrap();
        let lineage_ids: Vec<_> = lineage.iter().map(|item| item.lease_id.clone()).collect();
        assert_eq!(lineage_ids, [first.lease_id, second.lease_id]);
        assert_eq!(
            lineage[0].end.as_ref().unwrap().boundary,
            ProviderLeaseBoundary::Quota
        );

        assert_eq!(ledger.provider_lease_lanes().unwrap(), [lane_a, lane_b]);
    }
}
