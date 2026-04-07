//! Session CRUD operations.

use std::path::PathBuf;
use std::str::FromStr;

use sqlx::Row;

use ops_core::ToolKind;
use ops_core::id::{GroupId, SessionId};
use ops_core::session::{SessionRecord, SessionState};
use ops_core::trust::ExecutionClass;

use crate::Store;
use crate::error::StoreError;

impl Store {
    /// Insert a new session record.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] if the insert fails (e.g. duplicate ID)
    /// or [`StoreError::Serialization`] if enum serialization fails.
    pub async fn create_session(&self, record: &SessionRecord) -> Result<(), StoreError> {
        let id = record.id.to_string();
        let title = &record.title;
        let path = record.path.to_string_lossy().to_string();
        let tool = serde_json::to_string(&record.tool)?;
        let group_id = record.group.as_ref().map(ToString::to_string);
        let parent_id = record.parent.as_ref().map(ToString::to_string);
        let execution_class = serde_json::to_string(&record.execution_class)?;
        let sandboxed = record.sandboxed;
        let state = serde_json::to_string(&record.state)?;

        sqlx::query(
            "INSERT INTO sessions (id, title, path, tool, group_id, parent_id, \
             execution_class, sandboxed, state) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(title)
        .bind(&path)
        .bind(&tool)
        .bind(&group_id)
        .bind(&parent_id)
        .bind(&execution_class)
        .bind(sandboxed)
        .bind(&state)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Fetch a session by its unique ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SessionNotFound`] if no session exists with the
    /// given ID, or [`StoreError::Database`] on query failure.
    pub async fn get_session(&self, id: &SessionId) -> Result<SessionRecord, StoreError> {
        let id_str = id.to_string();
        let row = sqlx::query("SELECT * FROM sessions WHERE id = ?")
            .bind(&id_str)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => row_to_session(&row),
            None => Err(StoreError::SessionNotFound { id: id_str }),
        }
    }

    /// Fetch a session by its title (exact match).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SessionNotFound`] if no session exists with the
    /// given title, or [`StoreError::Database`] on query failure.
    pub async fn get_session_by_title(&self, title: &str) -> Result<SessionRecord, StoreError> {
        let row = sqlx::query("SELECT * FROM sessions WHERE title = ?")
            .bind(title)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => row_to_session(&row),
            None => Err(StoreError::SessionNotFound {
                id: title.to_string(),
            }),
        }
    }

    /// List all sessions ordered by creation time.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] on query failure.
    pub async fn list_sessions(&self) -> Result<Vec<SessionRecord>, StoreError> {
        let rows = sqlx::query("SELECT * FROM sessions ORDER BY created_at")
            .fetch_all(&self.pool)
            .await?;

        rows.iter().map(row_to_session).collect()
    }

    /// List sessions filtered by state.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] on query failure or
    /// [`StoreError::Serialization`] if the state cannot be serialized.
    pub async fn list_sessions_by_state(
        &self,
        state: SessionState,
    ) -> Result<Vec<SessionRecord>, StoreError> {
        let state_str = serde_json::to_string(&state)?;
        let rows = sqlx::query("SELECT * FROM sessions WHERE state = ? ORDER BY created_at")
            .bind(&state_str)
            .fetch_all(&self.pool)
            .await?;

        rows.iter().map(row_to_session).collect()
    }

    /// Update the state of a session.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SessionNotFound`] if the session does not exist,
    /// or [`StoreError::Database`] on query failure.
    pub async fn update_session_state(
        &self,
        id: &SessionId,
        state: SessionState,
    ) -> Result<(), StoreError> {
        let id_str = id.to_string();
        let state_str = serde_json::to_string(&state)?;

        let result =
            sqlx::query("UPDATE sessions SET state = ?, updated_at = datetime('now') WHERE id = ?")
                .bind(&state_str)
                .bind(&id_str)
                .execute(&self.pool)
                .await?;

        if result.rows_affected() == 0 {
            return Err(StoreError::SessionNotFound { id: id_str });
        }

        Ok(())
    }

    /// Delete a session by ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SessionNotFound`] if the session does not exist,
    /// or [`StoreError::Database`] on query failure.
    pub async fn delete_session(&self, id: &SessionId) -> Result<(), StoreError> {
        let id_str = id.to_string();

        let result = sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(&id_str)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(StoreError::SessionNotFound { id: id_str });
        }

        Ok(())
    }
}

/// Convert a raw `sqlx::Row` into a [`SessionRecord`].
fn row_to_session(row: &sqlx::sqlite::SqliteRow) -> Result<SessionRecord, StoreError> {
    let id_str: String = row.get("id");
    let id = SessionId::from_str(&id_str).map_err(|e| StoreError::SessionNotFound {
        id: format!("invalid session ID '{id_str}': {e}"),
    })?;

    let title: String = row.get("title");
    let path_str: String = row.get("path");
    let path = PathBuf::from(path_str);

    let tool_str: String = row.get("tool");
    let tool: ToolKind = serde_json::from_str(&tool_str)?;

    let group_id: Option<String> = row.get("group_id");
    let group = group_id.map(GroupId::new);

    let parent_str: Option<String> = row.get("parent_id");
    let parent = parent_str
        .map(|s| {
            SessionId::from_str(&s).map_err(|e| StoreError::SessionNotFound {
                id: format!("invalid parent ID '{s}': {e}"),
            })
        })
        .transpose()?;

    let exec_str: String = row.get("execution_class");
    let execution_class: ExecutionClass = serde_json::from_str(&exec_str)?;

    let sandboxed: bool = row.get("sandboxed");

    let state_str: String = row.get("state");
    let state: SessionState = serde_json::from_str(&state_str)?;

    Ok(SessionRecord {
        id,
        title,
        path,
        tool,
        group,
        parent,
        execution_class,
        sandboxed,
        state,
    })
}
