use tokio::time::{Duration, Instant};

pub const WINDOW_SIZE: u64 = 128;
pub const SESSION_HARD_TIMEOUT: Duration = Duration::from_secs(86400);
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(1800);

/// Maintains session validity and anti-replay state using a sliding-window
/// bitmask over the 128 most recent message counters.
pub struct SessionGuard {
    pub start_time: Instant,
    pub last_activity: Instant,
    pub v_max: u64,
    pub bitmask: u128,
}

impl SessionGuard {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            last_activity: Instant::now(),
            v_max: 0,
            bitmask: 0,
        }
    }

    /// Returns `true` if the session has not exceeded either the hard or idle
    /// timeout.
    pub fn is_valid(&self) -> bool {
        let now = Instant::now();
        now.duration_since(self.start_time) < SESSION_HARD_TIMEOUT
            && now.duration_since(self.last_activity) < SESSION_IDLE_TIMEOUT
    }

    /// Validates `counter` against the sliding window and — if accepted —
    /// updates the bitmask and refreshes the idle timer.
    ///
    /// Returns `false` for:
    /// - expired sessions
    /// - counters older than `v_max - WINDOW_SIZE` (outside window)
    /// - counters already present in the bitmask (replay)
    pub fn check_and_update(&mut self, counter: u64) -> bool {
        if !self.is_valid() {
            return false;
        }
        if counter > self.v_max {
            let shift = counter - self.v_max;
            if shift >= WINDOW_SIZE {
                self.bitmask = 1;
            } else {
                self.bitmask = (self.bitmask << shift) | 1;
            }
            self.v_max = counter;
            self.last_activity = Instant::now();
            true
        } else {
            if counter <= self.v_max.saturating_sub(WINDOW_SIZE) {
                return false;
            }
            let offset = (self.v_max - counter) as u32;
            if (self.bitmask & (1 << offset)) != 0 {
                return false;
            }
            self.bitmask |= 1 << offset;
            self.last_activity = Instant::now();
            true
        }
    }
}
