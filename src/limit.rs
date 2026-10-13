//! In-memory sliding-window rate limiter.
use crate::Lk;
use std::{collections::HashMap, sync::Mutex};

pub const WINDOW: i64 = 900; // longest window in use; purge() drops older hits

#[derive(Default)]
pub struct Limiter(Mutex<HashMap<String, Vec<i64>>>);

impl Limiter {
    /// Records a hit; false when `max` hits already happened within `window` seconds.
    pub fn hit(&self, key: &str, max: usize, window: i64, now: i64) -> bool {
        let mut m = self.0.lk();
        let v = m.entry(key.to_string()).or_default();
        v.retain(|t| *t > now - window);
        if v.len() >= max {
            return false;
        }
        v.push(now);
        true
    }
    // ponytail: process-local, lost on restart and not shared between instances
    pub fn purge(&self, now: i64) {
        self.0.lk().retain(|_, v| {
            v.retain(|t| *t > now - WINDOW);
            !v.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_and_purge() {
        let l = Limiter::default();
        assert!((0..3).all(|i| l.hit("a", 3, 100, 1000 + i)));
        assert!(!l.hit("a", 3, 100, 1010));
        assert!(l.hit("b", 3, 100, 1010)); // keys are independent
        assert!(l.hit("a", 3, 100, 1101)); // oldest hit left the window
        l.purge(1000 + WINDOW + 200);
        assert!(l.0.lk().is_empty());
    }
}
