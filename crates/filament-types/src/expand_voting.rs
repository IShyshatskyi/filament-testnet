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

// ── Chain-count arithmetic (clean-room port; checked against the node by the shared vectors) ──

/// Protocol maximum hash-sorting width.
pub const MAX_S_BITS: u8 = 12;

/// Most chains a block may commit to: `2^12 - 1`, the largest count the 12 packed bits of
/// `merged_mining_root` hold.
pub const MAX_COMMITTED_CHAIN_COUNT: u16 = (1u16 << MAX_S_BITS) - 1;

/// Smallest width `s >= 1` with `count <= 2^s - 1` (never shrinks below `current_s`).
/// Panics above the protocol maximum; use [`checked_s_bits_for_chain_count`] for untrusted counts.
pub fn compute_required_s_bits(new_count: u16, current_s: u8) -> u8 {
    let mut s = current_s;
    while (new_count as u32) > (1u32 << s).saturating_sub(1) {
        s += 1;
        assert!(s <= MAX_S_BITS, "shard count exceeds protocol maximum (s=12, cap=4095)");
    }
    if s == 0 {
        s = 1;
    }
    s
}

/// Pure count to width mapping.
pub fn s_bits_for_chain_count(count: u16) -> u8 {
    compute_required_s_bits(count, 0)
}

/// [`s_bits_for_chain_count`] for an untrusted count: `None` above [`MAX_COMMITTED_CHAIN_COUNT`].
pub fn checked_s_bits_for_chain_count(count: u16) -> Option<u8> {
    (count <= MAX_COMMITTED_CHAIN_COUNT).then(|| s_bits_for_chain_count(count))
}

/// Number of chains opened by one successful expand vote at `active_shard_count` chains: one below
/// four chains, else `max(1, count * num / den)`.
pub fn compute_step_with(active_shard_count: u16, step_numerator: u16, step_denominator: u16) -> u16 {
    if active_shard_count < 4 {
        return 1;
    }
    let step = (active_shard_count as u32 * step_numerator as u32) / step_denominator.max(1) as u32;
    step.max(1) as u16
}

/// Epochs of lag between a shard and the beacon that the admissible count range tolerates.
pub const SHARD_LAG_EPOCHS: u32 = 1;

/// `base` after `steps` consecutive expansion steps, capped at the protocol maximum.
pub fn count_after_steps(base: u16, steps: u32, step_numerator: u16, step_denominator: u16) -> u16 {
    let mut n = base;
    for _ in 0..steps {
        n = n
            .saturating_add(compute_step_with(n, step_numerator, step_denominator))
            .min(MAX_COMMITTED_CHAIN_COUNT);
    }
    n
}

/// Inclusive range of `committed_chain_count` a shard block of governance epoch `epoch` may carry,
/// with [`SHARD_LAG_EPOCHS`] of lag tolerated. `count_of(e)` is the active chain count recorded for
/// epoch `e` (`None` when the snapshot is missing).
pub fn shard_admissible_count_range(
    epoch: u32,
    count_of: impl Fn(u32) -> Option<u16>,
    step_numerator: u16,
    step_denominator: u16,
) -> Option<(u16, u16)> {
    if epoch == 0 {
        let c0 = count_of(0)?;
        return Some((c0, count_after_steps(c0, SHARD_LAG_EPOCHS, step_numerator, step_denominator)));
    }
    let prev = count_of(epoch - 1).or_else(|| count_of(epoch))?;
    let low = if epoch >= 2 { count_of(epoch - 2).unwrap_or(prev) } else { prev };
    let high = count_after_steps(prev, 1 + SHARD_LAG_EPOCHS, step_numerator, step_denominator);
    Some((low.min(prev), high))
}

/// Reference width of an epoch: the width of the ceiling of its admissible count range.
pub fn shard_reference_s_bits(count_range: (u16, u16)) -> u32 {
    s_bits_for_chain_count(count_range.1) as u32
}

/// Admissible width range for a count range.
pub fn admissible_s_bits_range(count_range: (u16, u16)) -> (u8, u8) {
    (s_bits_for_chain_count(count_range.0), s_bits_for_chain_count(count_range.1))
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
