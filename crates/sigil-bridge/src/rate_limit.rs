//! Simple window-based rate limiting.
//!
//! Tracks per-user message counts within sliding minute and hour windows.
//! When a window elapses, the counter resets. No external crate dependencies.

use std::collections::HashMap;

use time::OffsetDateTime;

use crate::error::BridgeError;

/// Default maximum messages per minute.
const DEFAULT_MAX_PER_MINUTE: u32 = 30;

/// Default maximum messages per hour.
const DEFAULT_MAX_PER_HOUR: u32 = 200;

/// Per-user rate limiter with minute and hour windows.
pub struct RateLimiter {
    limits: HashMap<String, UserLimitState>,
    max_per_minute: u32,
    max_per_hour: u32,
}

/// Tracks a single user's window state.
struct UserLimitState {
    minute_count: u32,
    minute_window_start: OffsetDateTime,
    hour_count: u32,
    hour_window_start: OffsetDateTime,
}

impl UserLimitState {
    fn new(now: OffsetDateTime) -> Self {
        Self {
            minute_count: 0,
            minute_window_start: now,
            hour_count: 0,
            hour_window_start: now,
        }
    }
}

impl RateLimiter {
    /// Create a rate limiter with the given per-minute and per-hour caps.
    #[must_use]
    pub fn new(max_per_minute: u32, max_per_hour: u32) -> Self {
        Self {
            limits: HashMap::new(),
            max_per_minute,
            max_per_hour,
        }
    }

    /// Create a rate limiter with sensible defaults (30/min, 200/hr).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_MAX_PER_MINUTE, DEFAULT_MAX_PER_HOUR)
    }

    /// Check whether `user_id` is currently rate-limited.
    ///
    /// Returns `Ok(())` if the user is within limits, or
    /// `Err(BridgeError::RateLimited)` if either window is exceeded.
    ///
    /// This does **not** increment counters — call [`record`](Self::record)
    /// after successfully processing the message.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::RateLimited`] when the user has exceeded
    /// the per-minute or per-hour message cap.
    pub fn check(&mut self, user_id: &str) -> Result<(), BridgeError> {
        let now = OffsetDateTime::now_utc();
        let state = self
            .limits
            .entry(user_id.to_owned())
            .or_insert_with(|| UserLimitState::new(now));

        // Reset minute window if elapsed.
        let minute_elapsed = now - state.minute_window_start;
        if minute_elapsed.whole_seconds() >= 60 {
            state.minute_count = 0;
            state.minute_window_start = now;
        }

        // Reset hour window if elapsed.
        let hour_elapsed = now - state.hour_window_start;
        if hour_elapsed.whole_seconds() >= 3600 {
            state.hour_count = 0;
            state.hour_window_start = now;
        }

        if state.minute_count >= self.max_per_minute {
            return Err(BridgeError::RateLimited {
                user_id: user_id.to_owned(),
            });
        }

        if state.hour_count >= self.max_per_hour {
            return Err(BridgeError::RateLimited {
                user_id: user_id.to_owned(),
            });
        }

        Ok(())
    }

    /// Record a message from `user_id`, incrementing both window counters.
    pub fn record(&mut self, user_id: &str) {
        let now = OffsetDateTime::now_utc();
        let state = self
            .limits
            .entry(user_id.to_owned())
            .or_insert_with(|| UserLimitState::new(now));

        state.minute_count += 1;
        state.hour_count += 1;
    }

    /// Internal constructor that accepts an explicit `now` for testing.
    #[cfg(test)]
    fn check_at(&mut self, user_id: &str, now: OffsetDateTime) -> Result<(), BridgeError> {
        let state = self
            .limits
            .entry(user_id.to_owned())
            .or_insert_with(|| UserLimitState::new(now));

        let minute_elapsed = now - state.minute_window_start;
        if minute_elapsed.whole_seconds() >= 60 {
            state.minute_count = 0;
            state.minute_window_start = now;
        }

        let hour_elapsed = now - state.hour_window_start;
        if hour_elapsed.whole_seconds() >= 3600 {
            state.hour_count = 0;
            state.hour_window_start = now;
        }

        if state.minute_count >= self.max_per_minute {
            return Err(BridgeError::RateLimited {
                user_id: user_id.to_owned(),
            });
        }

        if state.hour_count >= self.max_per_hour {
            return Err(BridgeError::RateLimited {
                user_id: user_id.to_owned(),
            });
        }

        Ok(())
    }

    /// Internal recorder with explicit timestamp for testing.
    #[cfg(test)]
    fn record_at(&mut self, user_id: &str, now: OffsetDateTime) {
        let state = self
            .limits
            .entry(user_id.to_owned())
            .or_insert_with(|| UserLimitState::new(now));

        state.minute_count += 1;
        state.hour_count += 1;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use time::Duration;

    use super::*;

    #[test]
    fn under_limit_is_allowed() {
        let mut limiter = RateLimiter::new(5, 100);
        assert!(limiter.check("user-1").is_ok());
    }

    #[test]
    fn at_minute_limit_is_denied() {
        let mut limiter = RateLimiter::new(3, 100);
        for _ in 0..3 {
            limiter.record("user-1");
        }
        let err = limiter.check("user-1").expect_err("should be rate limited");
        assert!(matches!(err, BridgeError::RateLimited { .. }));
    }

    #[test]
    fn at_hour_limit_is_denied() {
        let mut limiter = RateLimiter::new(1000, 5);
        for _ in 0..5 {
            limiter.record("user-1");
        }
        let err = limiter.check("user-1").expect_err("should be rate limited");
        assert!(matches!(err, BridgeError::RateLimited { .. }));
    }

    #[test]
    fn different_users_have_independent_limits() {
        let mut limiter = RateLimiter::new(2, 100);
        // Exhaust user-1's minute limit.
        limiter.record("user-1");
        limiter.record("user-1");
        assert!(limiter.check("user-1").is_err());

        // user-2 should still be fine.
        assert!(limiter.check("user-2").is_ok());
    }

    #[test]
    fn minute_window_resets_after_60s() {
        let mut limiter = RateLimiter::new(2, 100);
        let now = OffsetDateTime::now_utc();

        // Fill up the minute window.
        limiter.record_at("user-1", now);
        limiter.record_at("user-1", now);
        assert!(limiter.check_at("user-1", now).is_err());

        // Advance past the minute window.
        let later = now + Duration::seconds(61);
        assert!(limiter.check_at("user-1", later).is_ok());
    }

    #[test]
    fn new_user_starts_with_fresh_limits() {
        let mut limiter = RateLimiter::new(5, 100);
        // First check for a never-seen user should pass.
        assert!(limiter.check("brand-new-user").is_ok());
    }

    #[test]
    fn defaults_use_expected_values() {
        let limiter = RateLimiter::with_defaults();
        assert_eq!(limiter.max_per_minute, 30);
        assert_eq!(limiter.max_per_hour, 200);
    }
}
