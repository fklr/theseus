use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::errors::{Error, Result};

trait TimeSource: Send + Sync {
    fn now(&self) -> u64;
}
struct SystemClock;

impl TimeSource for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}

pub struct RateLimit {
    counter: AtomicU64,
    last_reset: AtomicU64,
    window: Duration,
    max_operations: u64,
    clock: Arc<dyn TimeSource>,
}

impl RateLimit {
    pub fn new(window: Duration, max_operations: u64) -> Self {
        Self::with_clock(window, max_operations, Arc::new(SystemClock))
    }

    fn with_clock(window: Duration, max_operations: u64, clock: Arc<dyn TimeSource>) -> Self {
        let now = clock.now();
        Self {
            counter: AtomicU64::new(0),
            last_reset: AtomicU64::new(now),
            window,
            max_operations,
            clock,
        }
    }

    pub fn check(&self) -> Result<()> {
        let now = self.clock.now();
        let last_reset = self.last_reset.load(Ordering::Acquire);

        if now.saturating_sub(last_reset) > self.window.as_millis() as u64 {
            self.counter.store(0, Ordering::Release);
            self.last_reset.store(now, Ordering::Release);
        }

        let current_count = self.counter.fetch_add(1, Ordering::AcqRel) + 1;
        if current_count > self.max_operations {
            Err(Error::rate_limited(
                "Rate limit exceeded",
                format!(
                    "Maximum operations ({}) exceeded in window of {} seconds",
                    self.max_operations,
                    self.window.as_secs()
                ),
            ))
        } else {
            Ok(())
        }
    }

    pub fn get_remaining(&self) -> u64 {
        let now = self.clock.now();
        let last_reset = self.last_reset.load(Ordering::Acquire);

        if now.saturating_sub(last_reset) > self.window.as_millis() as u64 {
            return self.max_operations;
        }

        let current_count = self.counter.load(Ordering::Acquire);
        self.max_operations.saturating_sub(current_count)
    }

    pub fn get_window_remaining(&self) -> Duration {
        let now = self.clock.now();
        let last_reset = self.last_reset.load(Ordering::Acquire);
        let elapsed = now.saturating_sub(last_reset);

        if elapsed >= self.window.as_millis() as u64 {
            Duration::from_millis(0)
        } else {
            Duration::from_millis(self.window.as_millis() as u64 - elapsed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockClock {
        now: AtomicU64,
    }

    impl TimeSource for MockClock {
        fn now(&self) -> u64 {
            self.now.load(Ordering::Acquire)
        }
    }

    impl MockClock {
        fn advance(&self, duration: Duration) {
            self.now
                .fetch_add(duration.as_millis() as u64, Ordering::Release);
        }
    }

    #[test]
    fn test_rate_limiting() {
        let limiter = RateLimit::new(Duration::from_secs(1), 5);

        // Should allow max_operations requests
        for _ in 0..5 {
            assert!(limiter.check().is_ok());
        }

        // Should deny additional requests
        assert!(limiter.check().is_err());
    }

    #[tokio::test]
    async fn test_window_reset() {
        let clock = Arc::new(MockClock {
            now: AtomicU64::new(0),
        });

        let limiter = RateLimit::with_clock(Duration::from_secs(1), 5, clock.clone());

        // Use up the limit
        for _ in 0..5 {
            assert!(limiter.check().is_ok());
        }
        assert!(limiter.check().is_err());

        // Advance clock past window
        clock.advance(Duration::from_secs(2));

        // Should allow operations again
        assert!(limiter.check().is_ok());
    }

    #[test]
    fn test_remaining_operations() {
        let limiter = RateLimit::new(Duration::from_secs(1), 5);

        assert_eq!(limiter.get_remaining(), 5);

        // Consume some operations
        for _ in 0..3 {
            limiter.check().unwrap();
        }

        assert_eq!(limiter.get_remaining(), 2);
    }

    #[test]
    fn test_window_remaining() {
        let window = Duration::from_secs(5);
        let limiter = RateLimit::new(window, 10);

        // Initial window
        let remaining = limiter.get_window_remaining();
        assert!(remaining <= window);
        assert!(remaining > Duration::from_secs(0));

        // After some operations
        for _ in 0..5 {
            limiter.check().unwrap();
        }

        let remaining = limiter.get_window_remaining();
        assert!(remaining <= window);
    }
}
