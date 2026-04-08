//! [`GrantStore`] trait implementation for `SQLite`.

use sqlx::Row;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use sigil_core::id::RequestId;
use sigil_core::trust::Capability;
use sigil_policy::PolicyError;
use sigil_policy::grants::{ApprovalGrant, GrantStore};

use crate::Store;
use crate::error::StoreError;

impl GrantStore for Store {
    async fn find_grant(
        &self,
        principal: &str,
        capability: Capability,
        resource: Option<&str>,
    ) -> Result<Option<ApprovalGrant>, PolicyError> {
        let cap_str = serde_json::to_string(&capability).map_err(StoreError::Serialization)?;
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default();

        // Fetch all potentially matching grants: right principal, right
        // capability, not yet expired.  We filter use-count and scope
        // in application code to keep the SQL simple.
        let rows = sqlx::query(
            "SELECT * FROM approval_grants \
             WHERE principal_id = ? AND capability = ? AND expires_at > ? \
             ORDER BY issued_at DESC",
        )
        .bind(principal)
        .bind(&cap_str)
        .bind(&now)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        for row in &rows {
            let grant = row_to_grant(row)?;
            if !grant.is_valid() {
                continue;
            }
            if grant.matches(principal, capability, resource) {
                return Ok(Some(grant));
            }
        }

        Ok(None)
    }

    async fn save_grant(&self, grant: &ApprovalGrant) -> Result<(), PolicyError> {
        let id = grant.id.to_string();
        let cap_str =
            serde_json::to_string(&grant.capability).map_err(StoreError::Serialization)?;
        let expires_at = grant.expires_at.format(&Rfc3339).unwrap_or_default();
        let issued_at = grant.issued_at.format(&Rfc3339).unwrap_or_default();

        sqlx::query(
            "INSERT INTO approval_grants \
             (id, principal_id, capability, resource_scope, expires_at, max_uses, uses, \
              issued_by, issued_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET \
             uses = excluded.uses, \
             expires_at = excluded.expires_at, \
             max_uses = excluded.max_uses",
        )
        .bind(&id)
        .bind(&grant.principal_id)
        .bind(&cap_str)
        .bind(&grant.resource_scope)
        .bind(&expires_at)
        .bind(grant.max_uses.map(i64::from))
        .bind(i64::from(grant.uses))
        .bind(&grant.issued_by)
        .bind(&issued_at)
        .execute(&self.pool)
        .await
        .map_err(StoreError::Database)?;

        Ok(())
    }
}

impl Store {
    /// Remove expired approval grants from the database.
    ///
    /// Deletes any grant whose `expires_at` is in the past, or whose
    /// `uses` has reached `max_uses`. Intended to be called periodically
    /// (e.g., once per heartbeat cycle).
    ///
    /// Returns the number of grants removed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] if the delete query fails.
    pub async fn cleanup_expired_grants(&self) -> Result<usize, StoreError> {
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default();

        let result = sqlx::query(
            "DELETE FROM approval_grants \
             WHERE expires_at <= ? \
                OR (max_uses IS NOT NULL AND uses >= max_uses)",
        )
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(usize::try_from(result.rows_affected()).unwrap_or(usize::MAX))
    }
}

/// Convert a raw `sqlx::Row` into an [`ApprovalGrant`].
fn row_to_grant(row: &sqlx::sqlite::SqliteRow) -> Result<ApprovalGrant, StoreError> {
    let id_str: String = row.get("id");
    let id = id_str
        .parse::<ulid::Ulid>()
        .map(RequestId::from_ulid)
        .map_err(|e| StoreError::SessionNotFound {
            id: format!("invalid grant ID '{id_str}': {e}"),
        })?;

    let principal_id: String = row.get("principal_id");

    let cap_str: String = row.get("capability");
    let capability: Capability = serde_json::from_str(&cap_str)?;

    let resource_scope: Option<String> = row.get("resource_scope");

    let expires_str: String = row.get("expires_at");
    let expires_at =
        OffsetDateTime::parse(&expires_str, &Rfc3339).map_err(|e| StoreError::SessionNotFound {
            id: format!("invalid expires_at '{expires_str}': {e}"),
        })?;

    let max_uses: Option<i64> = row.get("max_uses");
    let max_uses = max_uses.map(|v| u32::try_from(v).unwrap_or(u32::MAX));

    let uses: i64 = row.get("uses");
    let uses = u32::try_from(uses).unwrap_or(u32::MAX);

    let issued_by: String = row.get("issued_by");

    let issued_str: String = row.get("issued_at");
    let issued_at =
        OffsetDateTime::parse(&issued_str, &Rfc3339).map_err(|e| StoreError::SessionNotFound {
            id: format!("invalid issued_at '{issued_str}': {e}"),
        })?;

    Ok(ApprovalGrant {
        id,
        principal_id,
        capability,
        resource_scope,
        expires_at,
        max_uses,
        uses,
        issued_by,
        issued_at,
    })
}
