use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use ulid::Ulid;

/// Unique identifier for an agent session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(Ulid);

impl SessionId {
    #[must_use]
    pub fn new() -> Self {
        Self(Ulid::new())
    }

    #[must_use]
    pub fn from_ulid(id: Ulid) -> Self {
        Self(id)
    }

    #[must_use]
    pub fn as_ulid(&self) -> Ulid {
        self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for SessionId {
    type Err = ulid::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ulid::from_str(s).map(Self)
    }
}

/// Unique identifier for a session group.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(String);

impl GroupId {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Unique identifier for an approval request or grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(Ulid);

impl RequestId {
    #[must_use]
    pub fn new() -> Self {
        Self(Ulid::new())
    }

    #[must_use]
    pub fn from_ulid(id: Ulid) -> Self {
        Self(id)
    }

    #[must_use]
    pub fn as_ulid(&self) -> Ulid {
        self.0
    }
}

impl FromStr for RequestId {
    type Err = ulid::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ulid::from_str(s).map(Self)
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_roundtrips_through_string() {
        let id = SessionId::new();
        let s = id.to_string();
        let parsed: SessionId = s.parse().expect("valid ULID");
        assert_eq!(id, parsed);
    }

    #[test]
    fn group_id_displays_name() {
        let g = GroupId::new("daydream");
        assert_eq!(g.as_str(), "daydream");
        assert_eq!(g.to_string(), "daydream");
    }
}
