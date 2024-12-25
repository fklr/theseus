use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::errors::{Error, Result};

/// TimeSource trait for providing current time in milliseconds
pub trait TimeSource: Send + Sync {
    fn now(&self) -> u64;
}

/// System clock implementation using std::time
#[derive(Clone)]
struct SystemClock;

impl TimeSource for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// Mock clock for testing with manual time control
pub struct MockClock {
    pub now: AtomicU64,
}

impl TimeSource for MockClock {
    fn now(&self) -> u64 {
        self.now.load(Ordering::Acquire)
    }
}

impl MockClock {
    pub fn advance(&self, duration: Duration) {
        self.now
            .fetch_add(duration.as_millis() as u64, Ordering::Release);
    }
}

/// Window types for rate limiting
#[derive(Debug, Clone, Copy)]
pub enum WindowType {
    /// Standard fixed window
    Fixed,
    /// Sliding window with sub-window tracking
    Sliding { sub_windows: u32 },
}

/// Rate limiter with zero-allocation design and atomic operations
pub struct RateLimit {
    /// Operation counter using atomic integer
    counter: AtomicU64,
    /// Last reset timestamp
    last_reset: AtomicU64,
    /// Time window for rate limiting
    window: Duration,
    /// Maximum operations allowed per window
    max_operations: u64,
    /// Time source implementation
    clock: Arc<dyn TimeSource>,
    /// Window type configuration
    window_type: WindowType,
    /// Sub-window counters for sliding window
    sub_counters: Box<[AtomicU64]>,
}

impl RateLimit {
    /// Creates a new rate limiter with default system clock
    pub fn new(window: Duration, max_operations: u64) -> Self {
        Self::with_clock(window, max_operations, Arc::new(SystemClock))
    }

    /// Creates a new rate limiter with custom clock implementation
    pub fn with_clock(window: Duration, max_operations: u64, clock: Arc<dyn TimeSource>) -> Self {
        let now = clock.now();
        Self {
            counter: AtomicU64::new(0),
            last_reset: AtomicU64::new(now),
            window,
            max_operations,
            clock,
            window_type: WindowType::Fixed,
            sub_counters: Box::new([]),
        }
    }

    /// Creates a new rate limiter with sliding window
    pub fn new_sliding(window: Duration, max_operations: u64, sub_windows: u32) -> Self {
        let clock = Arc::new(SystemClock);
        let now = clock.now();
        Self {
            counter: AtomicU64::new(0),
            last_reset: AtomicU64::new(now),
            window,
            max_operations,
            clock,
            window_type: WindowType::Sliding { sub_windows },
            sub_counters: (0..sub_windows)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    /// Checks if operation is allowed under rate limit
    pub fn check(&self) -> Result<()> {
        let now = self.clock.now();
        let last_reset = self.last_reset.load(Ordering::Acquire);

        match self.window_type {
            WindowType::Fixed => self.check_fixed_window(now, last_reset),
            WindowType::Sliding { sub_windows } => {
                self.check_sliding_window(now, last_reset, sub_windows)
            }
        }
    }

    /// Gets remaining operations in current window
    pub fn get_remaining(&self) -> u64 {
        let now = self.clock.now();
        let last_reset = self.last_reset.load(Ordering::Acquire);

        if now.saturating_sub(last_reset) > self.window.as_millis() as u64 {
            return self.max_operations;
        }

        let current_count = match self.window_type {
            WindowType::Fixed => self.counter.load(Ordering::Acquire),
            WindowType::Sliding { .. } => self.get_sliding_window_count(),
        };

        self.max_operations.saturating_sub(current_count)
    }

    /// Gets remaining time in current window
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

    /// Gets window type configuration
    pub fn window_type(&self) -> WindowType {
        self.window_type
    }

    fn check_fixed_window(&self, now: u64, last_reset: u64) -> Result<()> {
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

    fn check_sliding_window(&self, now: u64, last_reset: u64, sub_windows: u32) -> Result<()> {
        let window_ms = self.window.as_millis() as u64;
        let sub_window_ms = window_ms / sub_windows as u64;
        let current_sub_window = (now / sub_window_ms) as usize % sub_windows as usize;

        if now.saturating_sub(last_reset) > window_ms {
            for counter in self.sub_counters.iter() {
                counter.store(0, Ordering::Release);
            }
            self.last_reset.store(now, Ordering::Release);
        }

        let current_count = self.get_sliding_window_count();
        if current_count >= self.max_operations {
            return Err(Error::rate_limited(
                "Rate limit exceeded",
                format!(
                    "Maximum operations ({}) exceeded in sliding window of {} seconds",
                    self.max_operations,
                    self.window.as_secs()
                ),
            ));
        }

        self.sub_counters[current_sub_window].fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn get_sliding_window_count(&self) -> u64 {
        self.sub_counters
            .iter()
            .map(|counter| counter.load(Ordering::Acquire))
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_window_rate_limiting() {
        let limiter = RateLimit::new(Duration::from_secs(1), 5);

        // Should allow max_operations requests
        for _ in 0..5 {
            assert!(limiter.check().is_ok());
        }

        // Should deny additional requests
        assert!(limiter.check().is_err());
    }

    #[tokio::test]
    async fn test_sliding_window() {
        let limiter = RateLimit::new_sliding(Duration::from_secs(1), 10, 2);

        // Fill first sub-window
        for _ in 0..5 {
            assert!(limiter.check().is_ok());
        }

        let clock = Arc::new(MockClock {
            now: AtomicU64::new(0),
        });

        // Advance to next sub-window
        clock.advance(Duration::from_millis(500));

        // Should allow more operations
        for _ in 0..5 {
            assert!(limiter.check().is_ok());
        }

        // Should deny when total across windows exceeds limit
        assert!(limiter.check().is_err());
    }

    #[test]
    fn test_window_reset() {
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

    #[test]
    fn test_concurrent_access() {
        let limiter = Arc::new(RateLimit::new(Duration::from_secs(1), 1000));
        let mut handles = Vec::new();

        for _ in 0..10 {
            let limiter = Arc::clone(&limiter);
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    let _ = limiter.check();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert!(limiter.get_remaining() <= 1000);
    }
}
