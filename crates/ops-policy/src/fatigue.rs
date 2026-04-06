//! Approval fatigue mitigation.
//!
//! Tracks the frequency of approval requests and enforces cooldown
//! periods when the rate exceeds a threshold. This prevents humans
//! from entering "auto-approve" mode when bombarded with too many
//! consecutive approval prompts.

use std::collections::VecDeque;

use time::OffsetDateTime;

use crate::error::PolicyError;

/// Default: 10 requests within 5 minutes triggers high-risk.
const DEFAULT_THRESHOLD: usize = 10;
/// Default window: 5 minutes (300 seconds).
const DEFAULT_WINDOW_SECS: i64 = 300;
/// Mandatory cooldown after high-risk detection: 2 minutes.
const COOLDOWN_SECS: i64 = 120;

/// Tracks approval request frequency to detect potential fatigue.
#[derive(Debug)]
pub struct FatigueGuard {
    /// Recent approval request timestamps.
    recent_requests: VecDeque<OffsetDateTime>,
    /// Maximum requests in the window before entering high-risk.
    threshold: usize,
    /// Sliding window duration in seconds.
    window_secs: i64,
    /// When high-risk was last detected (for cooldown enforcement).
    last_high_risk: Option<OffsetDateTime>,
}

impl Default for FatigueGuard {
    fn default() -> Self {
        Self::new(DEFAULT_THRESHOLD, DEFAULT_WINDOW_SECS)
    }
}

impl FatigueGuard {
    /// Create a new fatigue guard with the given threshold and window.
    ///
    /// - `threshold`: Number of requests within `window_secs` that
    ///   triggers `HighRisk`.
    /// - `window_secs`: Duration of the sliding window in seconds.
    #[must_use]
    pub fn new(threshold: usize, window_secs: i64) -> Self {
        Self {
            recent_requests: VecDeque::new(),
            threshold,
            window_secs,
            last_high_risk: None,
        }
    }

    /// Record an approval request and return the current fatigue level.
    ///
    /// Adds the current timestamp, prunes entries outside the sliding
    /// window, then evaluates:
    /// - `HighRisk` if count > threshold (also records the high-risk
    ///   timestamp for cooldown enforcement).
    /// - `Warning` if count > threshold / 2.
    /// - `Normal` otherwise.
    pub fn record_request(&mut self) -> FatigueLevel {
        let now = OffsetDateTime::now_utc();
        self.recent_requests.push_back(now);
        self.prune(now);

        let count = self.recent_requests.len();
        let half = self.threshold / 2;

        if count > self.threshold {
            self.last_high_risk = Some(now);
            FatigueLevel::HighRisk
        } else if count > half {
            FatigueLevel::Warning
        } else {
            FatigueLevel::Normal
        }
    }

    /// Check whether a mandatory cooldown is active.
    ///
    /// After a `HighRisk` detection, a 2-minute cooldown period is
    /// enforced during which no new approval requests should be issued.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::FatigueCooldown`] if the cooldown is
    /// still active.
    pub fn check_cooldown(&self) -> Result<(), PolicyError> {
        let Some(high_risk_at) = self.last_high_risk else {
            return Ok(());
        };

        let now = OffsetDateTime::now_utc();
        let elapsed = (now - high_risk_at).whole_seconds();

        if elapsed < COOLDOWN_SECS {
            Err(PolicyError::FatigueCooldown {
                cooldown_remaining_secs: COOLDOWN_SECS - elapsed,
            })
        } else {
            Ok(())
        }
    }

    /// Remove entries older than the sliding window.
    fn prune(&mut self, now: OffsetDateTime) {
        let cutoff = now - time::Duration::seconds(self.window_secs);
        while self
            .recent_requests
            .front()
            .is_some_and(|&ts| ts < cutoff)
        {
            self.recent_requests.pop_front();
        }
    }

    /// Number of requests currently in the window (for testing /
    /// diagnostics).
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.recent_requests.len()
    }
}

/// The fatigue state after recording a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatigueLevel {
    /// Normal operation.
    Normal,
    /// Approaching threshold -- log warnings.
    Warning,
    /// Too many requests -- enforce cooldown.
    HighRisk,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_guard_returns_normal() {
        let guard = FatigueGuard::default();
        // No requests recorded, cooldown should be clear.
        assert!(guard.check_cooldown().is_ok());
        assert_eq!(guard.active_count(), 0);
    }

    #[test]
    fn under_threshold_returns_normal() {
        // threshold=10, half=5. Record 3 requests -> Normal.
        let mut guard = FatigueGuard::new(10, 300);
        for _ in 0..3 {
            let level = guard.record_request();
            assert_eq!(level, FatigueLevel::Normal);
        }
    }

    #[test]
    fn at_half_threshold_returns_warning() {
        // threshold=10, half=5. 6th request crosses half -> Warning.
        let mut guard = FatigueGuard::new(10, 300);
        for _ in 0..5 {
            guard.record_request();
        }
        // 5 is at half, not past. The 6th should trigger Warning.
        let level = guard.record_request();
        assert_eq!(level, FatigueLevel::Warning);
    }

    #[test]
    fn over_threshold_returns_high_risk() {
        // threshold=10. 11th request crosses threshold -> HighRisk.
        let mut guard = FatigueGuard::new(10, 300);
        for _ in 0..10 {
            guard.record_request();
        }
        let level = guard.record_request();
        assert_eq!(level, FatigueLevel::HighRisk);
    }

    #[test]
    fn cooldown_enforced_after_high_risk() {
        let mut guard = FatigueGuard::new(10, 300);
        // Push past threshold.
        for _ in 0..11 {
            guard.record_request();
        }
        // Cooldown should now be active.
        let result = guard.check_cooldown();
        assert!(result.is_err(), "cooldown should be active after HighRisk");
    }

    #[test]
    fn cooldown_clear_when_no_high_risk() {
        let mut guard = FatigueGuard::new(10, 300);
        for _ in 0..3 {
            guard.record_request();
        }
        assert!(
            guard.check_cooldown().is_ok(),
            "no cooldown without HighRisk"
        );
    }

    #[test]
    fn old_requests_are_pruned() {
        // Use a tiny window of 1 second so we can test pruning
        // by injecting timestamps manually.
        let mut guard = FatigueGuard::new(10, 1);

        // Insert timestamps that are definitely outside the window.
        let old = OffsetDateTime::now_utc() - time::Duration::seconds(10);
        for _ in 0..5 {
            guard.recent_requests.push_back(old);
        }

        // Recording a new request should prune the old ones.
        let level = guard.record_request();
        assert_eq!(level, FatigueLevel::Normal);
        assert_eq!(guard.active_count(), 1, "old entries should have been pruned");
    }

    #[test]
    fn small_threshold_boundary_conditions() {
        // threshold=2, half=1. 2 requests -> Warning, 3 -> HighRisk.
        let mut guard = FatigueGuard::new(2, 300);

        assert_eq!(guard.record_request(), FatigueLevel::Normal);   // 1 <= 1
        assert_eq!(guard.record_request(), FatigueLevel::Warning);  // 2 > 1
        assert_eq!(guard.record_request(), FatigueLevel::HighRisk); // 3 > 2
    }
}
