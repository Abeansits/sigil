//! Operational memory for sigil sessions.
//!
//! `sigil-memory` captures episode events during sessions and applies
//! mechanical consolidation rules to promote candidate learnings into
//! `LEARNINGS.md`. It is the operational counterpart to `sigil-audit`:
//! while `sigil-audit` maintains a tamper-evident security log,
//! `sigil-memory` manages the agent's working memory.
//!
//! # Key Types
//!
//! - [`EpisodeWriter`] — append-only JSONL writer for `episodes.jsonl`.
//! - [`EpisodeReader`] — reads and filters episodes from the log.
//! - [`MechanicalConsolidator`] — pure-function consolidation engine.
//! - [`ConsolidationResult`] — output of a consolidation pass.
//! - [`MemoryError`] — error enum for memory operations.
//!
//! # Architecture
//!
//! Episode events ([`sigil_core::EpisodeEvent`]) are domain types defined
//! in `sigil-core`. This crate provides the writer, reader, and
//! consolidation logic. The consolidator does not touch the filesystem;
//! the caller handles all I/O.

pub mod consolidator;
pub mod error;
pub mod reader;
pub mod writer;

pub use consolidator::{ConsolidationResult, MechanicalConsolidator};
pub use error::MemoryError;
pub use reader::{EpisodeFilter, EpisodeReader};
pub use writer::EpisodeWriter;
