// Per-process block interval configuration (devnet DAA tuning).
//
// Production defaults: beacon 600 s, shard 37.5 s (75/2).
// Devnet may override via `init_block_intervals` at startup from
// `config/devnet_daa.toml` (e.g. 150 s / 9.375 s for a 4× faster soak).

use std::sync::OnceLock;

pub const DEFAULT_BEACON_INTERVAL_SECS: u64 = 600;
pub const DEFAULT_SHARD_INTERVAL_NUM: u64 = 75;
pub const DEFAULT_SHARD_INTERVAL_DEN: u64 = 2;

static BEACON_INTERVAL_CELL: OnceLock<u64> = OnceLock::new();
static SHARD_INTERVAL_NUM_CELL: OnceLock<u64> = OnceLock::new();
static SHARD_INTERVAL_DEN_CELL: OnceLock<u64> = OnceLock::new();

/// Set once at process startup from the loaded DAA config.
pub fn init_block_intervals(beacon_secs: u64, shard_secs: f64) {
    let beacon = beacon_secs.max(1);
    let (num, den) = shard_seconds_to_rational(shard_secs);
    let _ = BEACON_INTERVAL_CELL.set(beacon);
    let _ = SHARD_INTERVAL_NUM_CELL.set(num);
    let _ = SHARD_INTERVAL_DEN_CELL.set(den.max(1));
}

fn shard_seconds_to_rational(secs: f64) -> (u64, u64) {
    const CANDIDATES: [(f64, u64, u64); 4] = [
        (600.0, 600, 1),
        (150.0, 150, 1),
        (37.5, 75, 2),
        (9.375, 75, 8),
    ];
    for (s, n, d) in CANDIDATES {
        if (secs - s).abs() < 1e-6 {
            return (n, d);
        }
    }
    let rounded = secs.round() as u64;
    (rounded.max(1), 1)
}

#[inline]
pub fn beacon_interval_secs() -> u64 {
    *BEACON_INTERVAL_CELL
        .get()
        .unwrap_or(&DEFAULT_BEACON_INTERVAL_SECS)
}

#[inline]
pub fn shard_interval_num() -> u64 {
    *SHARD_INTERVAL_NUM_CELL
        .get()
        .unwrap_or(&DEFAULT_SHARD_INTERVAL_NUM)
}

#[inline]
pub fn shard_interval_den() -> u64 {
    *SHARD_INTERVAL_DEN_CELL
        .get()
        .unwrap_or(&DEFAULT_SHARD_INTERVAL_DEN)
}

/// Median-time-past slack: `6 × interval × 256` delta units.
#[inline]
pub fn beacon_mtp_offset() -> i32 {
    beacon_interval_secs()
        .saturating_mul(6 * 256)
        .min(i32::MAX as u64) as i32
}

#[inline]
pub fn shard_mtp_offset() -> i32 {
    let num = shard_interval_num() as i128;
    let den = shard_interval_den().max(1) as i128;
    ((num * 6 * 256) / den).min(i32::MAX as i128) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_production() {
        assert_eq!(beacon_interval_secs(), 600);
        assert_eq!(shard_interval_num(), 75);
        assert_eq!(shard_interval_den(), 2);
        assert_eq!(beacon_mtp_offset(), 921_600);
        assert_eq!(shard_mtp_offset(), 57_600);
    }

    #[test]
    fn devnet_4x_rational_values() {
        assert_eq!(shard_seconds_to_rational(9.375), (75, 8));
        assert_eq!(shard_seconds_to_rational(150.0), (150, 1));
        // MTP offsets at 4× speed (not applied until init_block_intervals at startup).
        assert_eq!(150_u64 * 6 * 256, 230_400);
        assert_eq!(75_u64 * 6 * 256 / 8, 14_400);
    }
}
