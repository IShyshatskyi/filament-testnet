/// K-coefficient voting configuration (consensus-critical).
///
/// Governs how miners vote on the per-epoch decline of the k-coefficient.
/// All parameters are serializable for genesis-config inclusion.
///
/// # Background
///
/// Miners embed a 1-bit vote (`vote_k_flag` in the block version field) on
/// every block.  At each epoch boundary the tally picks one of two
/// multiplicative steps, and **both are declines**: k never rises above its
/// genesis value (owner decision, Sep 30, 2026 — NC-118).
///
/// * a strict majority of blocks set the bit → the **slow** decline
///   (default ×991/1000, −0.9% per epoch);
/// * otherwise (including a tie) → the **fast** decline
///   (default ×985/1000, −1.5% per epoch).
///
/// A simple majority is deliberate: this vote repeats every epoch and each
/// outcome is small and reversible in effect (the next epoch votes again).
/// One-time votes with a lasting, irreversible effect — opening a shard
/// chain, a protocol update — use a supermajority instead (see
/// `expand_voting.rs`, `Protocol_Update_Voting_Design.md`).
///
/// The resulting k is encoded in [`KBits`] compact format and published to
/// shard chains via `ShardParameters`.
///
/// See `K_VOTING_DESIGN_v4.md` for the design history.

use serde::{Deserialize, Serialize};
use crate::common::crypto::k_bits::{ONE_KBITS, MIN_KBITS};

/// K-voting configuration embedded in genesis.
///
/// `#[serde(default)]` on every field ensures backward compatibility with
/// genesis configs that predate k-voting (they receive the standard defaults).
/// The step fields also accept their pre-Sep-30-2026 names
/// (`step_up_*` = slow decline, `step_down_*` = fast decline).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KVotingConfig {
    /// Initial k-coefficient encoded in KBits — also the largest value k can
    /// ever have, since every step is a decline.
    ///
    /// Defaults to `ONE_KBITS` (k = 1.0).
    #[serde(default = "default_k_initial_kbits")]
    pub k_initial_kbits: u32,

    /// Minimum allowed k, encoded in KBits.
    ///
    /// A structural floor only: the smallest value KBits can represent
    /// (`MIN_KBITS`, k_encoded = 1, k = 2^-48). Shard difficulty, not k, keeps
    /// mining worthwhile as k declines (`K_VOTING_DESIGN_v4.md` §0.2).
    #[serde(default = "default_k_min_kbits")]
    pub k_min_kbits: u32,

    /// Activation height: k-voting is ignored below this height.
    ///
    /// Allows a grace period at chain launch.  Default: first epoch (4096).
    #[serde(default = "default_activation_height")]
    pub activation_height: u32,

    /// Slow-decline multiplier numerator, applied when a strict majority of
    /// the epoch's blocks set `vote_k_flag`.
    /// New k = k × (slow_decline_num / slow_decline_den).
    ///
    /// A fraction to avoid floating point in consensus code.
    /// Default: 991/1000 = −0.9% per epoch.
    #[serde(default = "default_slow_decline_num", alias = "step_up_num")]
    pub slow_decline_num: u32,

    /// Slow-decline multiplier denominator.
    #[serde(default = "default_slow_decline_den", alias = "step_up_den")]
    pub slow_decline_den: u32,

    /// Fast-decline multiplier numerator, applied otherwise (no strict majority,
    /// including a tie).  New k = k × (fast_decline_num / fast_decline_den).
    ///
    /// Default: 985/1000 = −1.5% per epoch.
    #[serde(default = "default_fast_decline_num", alias = "step_down_num")]
    pub fast_decline_num: u32,

    /// Fast-decline multiplier denominator.
    #[serde(default = "default_fast_decline_den", alias = "step_down_den")]
    pub fast_decline_den: u32,
}

impl Default for KVotingConfig {
    fn default() -> Self {
        Self {
            k_initial_kbits: default_k_initial_kbits(),
            k_min_kbits: default_k_min_kbits(),
            activation_height: default_activation_height(),
            slow_decline_num: default_slow_decline_num(),
            slow_decline_den: default_slow_decline_den(),
            fast_decline_num: default_fast_decline_num(),
            fast_decline_den: default_fast_decline_den(),
        }
    }
}

fn default_k_initial_kbits() -> u32 { ONE_KBITS }

/// k_min = the smallest representable KBits value (k_encoded = 1, k = 2^-48).
fn default_k_min_kbits() -> u32 { MIN_KBITS }

fn default_activation_height()   -> u32 { 4_096 }
fn default_slow_decline_num()    -> u32 {   991 }
fn default_slow_decline_den()    -> u32 { 1_000 }
fn default_fast_decline_num()    -> u32 {   985 }
fn default_fast_decline_den()    -> u32 { 1_000 }

impl KVotingConfig {
    /// Validate that the config is internally consistent.
    ///
    /// Both steps must be declines (`0 < num < den`), and the fast decline
    /// must be at least as steep as the slow one.
    pub fn validate(&self) -> Result<(), String> {
        if self.k_initial_kbits == 0 {
            return Err("k_initial_kbits must be non-zero".to_string());
        }
        if self.k_min_kbits == 0 {
            return Err("k_min_kbits must be non-zero".to_string());
        }
        if self.slow_decline_den == 0 || self.fast_decline_den == 0 {
            return Err("step denominators must be non-zero".to_string());
        }
        if self.slow_decline_num == 0 || self.slow_decline_num >= self.slow_decline_den {
            return Err("slow decline must satisfy 0 < slow_decline_num < slow_decline_den (k never rises)".to_string());
        }
        if self.fast_decline_num == 0 || self.fast_decline_num >= self.fast_decline_den {
            return Err("fast decline must satisfy 0 < fast_decline_num < fast_decline_den (k never rises)".to_string());
        }
        // fast ≤ slow  ⇔  fast_num × slow_den ≤ slow_num × fast_den
        if (self.fast_decline_num as u64) * (self.slow_decline_den as u64)
            > (self.slow_decline_num as u64) * (self.fast_decline_den as u64)
        {
            return Err("fast decline must be at least as steep as the slow decline".to_string());
        }
        let k_init_enc = crate::common::crypto::k_bits::decode_kbits_u128(self.k_initial_kbits);
        let k_min_enc = crate::common::crypto::k_bits::decode_kbits_u128(self.k_min_kbits);
        if k_init_enc == 0 {
            return Err("k_initial_kbits does not decode to a positive k_encoded".to_string());
        }
        if k_init_enc < k_min_enc {
            return Err(format!(
                "k_initial ({}) must be ≥ k_min ({})",
                k_init_enc, k_min_enc,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::crypto::k_bits::{kbits_to_float, ONE_KBITS};

    #[test]
    fn default_config_is_valid() {
        let cfg = KVotingConfig::default();
        cfg.validate().expect("default KVotingConfig must be valid");
    }

    #[test]
    fn default_initial_k_is_one() {
        let cfg = KVotingConfig::default();
        assert_eq!(cfg.k_initial_kbits, ONE_KBITS);
        let k = kbits_to_float(cfg.k_initial_kbits);
        assert!((k - 1.0).abs() < 1e-9);
    }

    #[test]
    fn default_steps_are_asymmetric_declines() {
        let cfg = KVotingConfig::default();
        assert_eq!((cfg.slow_decline_num, cfg.slow_decline_den), (991, 1000), "slow = -0.9%");
        assert_eq!((cfg.fast_decline_num, cfg.fast_decline_den), (985, 1000), "fast = -1.5%");
    }

    #[test]
    fn default_k_min_is_smallest_representable() {
        assert_eq!(KVotingConfig::default().k_min_kbits, crate::common::crypto::k_bits::MIN_KBITS);
        assert_eq!(crate::common::crypto::k_bits::decode_kbits(KVotingConfig::default().k_min_kbits), 1);
    }

    #[test]
    fn validate_rejects_a_rising_step() {
        let mut cfg = KVotingConfig::default();
        cfg.slow_decline_num = 1001;
        assert!(cfg.validate().is_err(), "a step > 1 would let k rise");
        let mut cfg = KVotingConfig::default();
        cfg.fast_decline_num = 1000;
        assert!(cfg.validate().is_err(), "a step of exactly 1 is not a decline");
    }

    #[test]
    fn validate_rejects_fast_shallower_than_slow() {
        let mut cfg = KVotingConfig::default();
        cfg.fast_decline_num = 995;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn legacy_step_field_names_still_parse() {
        let cfg: KVotingConfig = toml::from_str(
            "step_up_num = 995\nstep_up_den = 1000\nstep_down_num = 980\nstep_down_den = 1000\n",
        ).unwrap();
        assert_eq!((cfg.slow_decline_num, cfg.fast_decline_num), (995, 980));
    }
}
