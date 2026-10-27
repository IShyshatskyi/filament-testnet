// filament-types/src/expand_voting.rs
//
// The governance epoch length, as a per-process value. A light client needs it to
// turn a block height into a governance epoch; it must come from the network the
// client talks to, never from a constant of the client.

use std::sync::OnceLock;

/// Epoch length used when the process never called [`init_epoch_length`].
pub const DEFAULT_EPOCH_LENGTH: u32 = 4096;

static EPOCH_LENGTH_CELL: OnceLock<u32> = OnceLock::new();

thread_local! {
    static EPOCH_LENGTH_TEST_OVERRIDE: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// Set the process-wide epoch length from the active network's profile. Call it once,
/// at startup, before any epoch is computed. Calling it again with the same value is
/// harmless; a different value panics, because two epoch lengths in one process would
/// silently disagree about every epoch boundary.
pub fn init_epoch_length(value: u32) {
    if EPOCH_LENGTH_CELL.set(value).is_err() {
        let existing = *EPOCH_LENGTH_CELL.get().expect("occupied after a failed set");
        assert_eq!(
            existing, value,
            "epoch_length already initialised to {existing}, cannot reinitialise to {value}"
        );
    }
}

/// The epoch length in blocks: the value from [`init_epoch_length`], else
/// [`DEFAULT_EPOCH_LENGTH`].
#[inline]
pub fn epoch_length() -> u32 {
    if let Some(v) = EPOCH_LENGTH_TEST_OVERRIDE.with(|c| c.get()) {
        return v;
    }
    *EPOCH_LENGTH_CELL.get().unwrap_or(&DEFAULT_EPOCH_LENGTH)
}

/// **Tests only.** Override the epoch length for the current thread, so tests that need
/// different values can run side by side in one process.
pub fn set_epoch_length_for_test(value: u32) {
    EPOCH_LENGTH_TEST_OVERRIDE.with(|c| c.set(Some(value)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_then_per_thread_override() {
        assert_eq!(epoch_length(), DEFAULT_EPOCH_LENGTH);
        set_epoch_length_for_test(8);
        assert_eq!(epoch_length(), 8);
        // another thread still sees the default
        assert_eq!(std::thread::spawn(epoch_length).join().unwrap(), DEFAULT_EPOCH_LENGTH);
    }
}
