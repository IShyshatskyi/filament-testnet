// src/common/blocks/version.rs
//
// Bitcoin-style version field with bit fields for special purposes.
//
// VERSION FIELD STRUCTURE (32 bits / 4 bytes)
// ============================================
//
// Bits 0-3:   Hash-sorting number (s) - 4 bits (values 0-15)
// Bit 4:      Vote K flag - 1 bit (0 or 1)
// Bit 5:      Vote Expand flag - 1 bit (0 or 1)
// Bits 6-31:  Base version number - 26 bits
//
// The version field follows Bitcoin's approach of encoding multiple pieces
// of information in a single 32-bit integer. This allows for:
// - Compact representation
// - Easy serialization (already part of block header)
// - Backward compatibility (older software sees it as just a version number)
// - Future extensibility (26 bits for version numbers)
//
// HASH-SORTING NUMBER (s)
// =======================
//
// The hash-sorting number (s) determines how many bits of a block hash are
// used to assign blocks to shards. With s=4, we get 2^4 - 1 = 15 possible
// shards (value 0 is reserved).
//
// Valid values: 0-15 (4 bits)
// - s=0:  No hash-sorting (beacon-only or single shard)
// - s=4:  15 shards (typical for small networks)
// - s=8:  255 shards (typical for medium networks)
// - s=12: 4095 shards (large networks)
// - s=15: 32767 shards (maximum)
//
// The s value is encoded in the beacon block version field and applies to
// the entire merged mining tree for that block.
//
// VOTE K FLAG (bit 4)
// ===================
//
// The vote_k_flag is used for voting on changes to the k parameter
// (which is separate from the hash-sorting number s).
// - 0: No vote or vote against k change
// - 1: Vote for k change
//
// VOTE EXPAND FLAG (bit 5)
// =========================
//
// The vote_expand_flag is used for voting on network expansion.
// - 0: No vote or vote against expansion
// - 1: Vote for expansion
//
// EXAMPLE VERSION VALUES
// ======================
//
// Version 1, s=0, no votes:           0x00000040 (0b01 000000)
// Version 1, s=4, no votes:           0x00000044 (0b01 000100)
// Version 1, s=4, vote_k=1:           0x00000054 (0b01 010100)
// Version 1, s=4, vote_expand=1:      0x00000064 (0b01 100100)
// Version 1, s=4, both votes:         0x00000074 (0b01 110100)
// Version 2, s=8, both votes:         0x000000F8 (0b10 111000)
//
// BITCOIN COMPATIBILITY
// =====================
//
// This follows Bitcoin's BIP 9 pattern of using version bits for signaling,
// though we're using them for configuration rather than soft fork signaling.
// The version field is part of the 80-byte mining header, so it's covered
// by proof-of-work.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Bitcoin-style version field with embedded hash-sorting number and vote flags.
///
/// The version field is a 32-bit unsigned integer that encodes:
/// - Hash-sorting parameter (s) in bits 0-3
/// - Vote K flag in bit 4
/// - Vote Expand flag in bit 5
/// - Base version number in bits 6-31
///
/// This allows the version to be backward compatible while carrying
/// additional consensus-critical information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockVersion(u32);

impl BlockVersion {
    // Bit masks for extracting fields
    const S_MASK: u32 = 0x0000000F;            // Bits 0-3: hash-sorting number
    const VOTE_K_MASK: u32 = 0x00000010;       // Bit 4: vote k flag
    const VOTE_EXPAND_MASK: u32 = 0x00000020;  // Bit 5: vote expand flag
    const VERSION_MASK: u32 = 0xFFFFFFC0;      // Bits 6-31: base version
    
    const S_SHIFT: u32 = 0;       // s is in bits 0-3
    const VOTE_K_SHIFT: u32 = 4;  // vote_k is bit 4
    const VOTE_EXPAND_SHIFT: u32 = 5;  // vote_expand is bit 5
    const VERSION_SHIFT: u32 = 6; // version starts at bit 6
    
    /// Create a new version field from base version, hash-sorting number, and vote flags.
    ///
    /// # Arguments
    /// * `base_version` - The base version number (will be shifted to bits 6-31)
    /// * `s` - Hash-sorting number (0-15, will be placed in bits 0-3)
    /// * `vote_k` - Vote K flag (bit 4)
    /// * `vote_expand` - Vote Expand flag (bit 5)
    ///
    /// # Panics
    /// Panics if s > 15 (doesn't fit in 4 bits)
    ///
    /// # Examples
    /// ```
    /// use common_types::common::blocks::BlockVersion;
    ///
    /// // Version 1 with s=4 (15 shards), no votes
    /// let version = BlockVersion::new(1, 4, false, false);
    /// assert_eq!(version.base_version(), 1);
    /// assert_eq!(version.s(), 4);
    /// assert_eq!(version.vote_k_flag(), false);
    /// assert_eq!(version.vote_expand_flag(), false);
    ///
    /// // Version 1 with s=4, vote for k change
    /// let version = BlockVersion::new(1, 4, true, false);
    /// assert_eq!(version.vote_k_flag(), true);
    /// ```
    pub fn new(base_version: u32, s: u8, vote_k: bool, vote_expand: bool) -> Self {
        assert!(s <= 15, "s must be 0-15 (4 bits), got {}", s);
        
        // Clear the lower 6 bits of base_version (just in case)
        let base = (base_version & (Self::VERSION_MASK >> Self::VERSION_SHIFT)) << Self::VERSION_SHIFT;
        
        // Set s in bits 0-3
        let s_bits = (s as u32) & Self::S_MASK;
        
        // Set vote_k in bit 4
        let vote_k_bits = if vote_k { Self::VOTE_K_MASK } else { 0 };
        
        // Set vote_expand in bit 5
        let vote_expand_bits = if vote_expand { Self::VOTE_EXPAND_MASK } else { 0 };
        
        Self(base | s_bits | vote_k_bits | vote_expand_bits)
    }
    
    /// Create version from raw u32 value.
    ///
    /// Use this when deserializing from storage or network.
    ///
    /// # Examples
    /// ```
    /// use common_types::common::blocks::BlockVersion;
    ///
    /// let version = BlockVersion::from_u32(0x00000044);
    /// assert_eq!(version.base_version(), 1);
    /// assert_eq!(version.s(), 4);
    /// ```
    pub fn from_u32(value: u32) -> Self {
        Self(value)
    }
    
    /// Get the raw u32 value.
    ///
    /// Use this when serializing to storage or network.
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    
    /// Extract the hash-sorting number (s) from the version field.
    ///
    /// The s value is stored in bits 0-3 of the version field.
    ///
    /// # Returns
    /// Hash-sorting number (0-15)
    ///
    /// # Examples
    /// ```
    /// use common_types::common::blocks::BlockVersion;
    ///
    /// let version = BlockVersion::new(1, 4, false, false);
    /// assert_eq!(version.s(), 4);
    ///
    /// let version = BlockVersion::new(1, 0, false, false);
    /// assert_eq!(version.s(), 0);
    ///
    /// let version = BlockVersion::new(1, 15, false, false);
    /// assert_eq!(version.s(), 15);
    /// ```
    pub fn s(&self) -> u8 {
        ((self.0 & Self::S_MASK) >> Self::S_SHIFT) as u8
    }
    
    /// Extract the Vote K flag from the version field.
    ///
    /// The vote_k flag is stored in bit 4 of the version field.
    ///
    /// # Returns
    /// true if vote k flag is set, false otherwise
    ///
    /// # Examples
    /// ```
    /// use common_types::common::blocks::BlockVersion;
    ///
    /// let version = BlockVersion::new(1, 4, true, false);
    /// assert_eq!(version.vote_k_flag(), true);
    ///
    /// let version = BlockVersion::new(1, 4, false, false);
    /// assert_eq!(version.vote_k_flag(), false);
    /// ```
    pub fn vote_k_flag(&self) -> bool {
        (self.0 & Self::VOTE_K_MASK) != 0
    }
    
    /// Extract the Vote Expand flag from the version field.
    ///
    /// The vote_expand flag is stored in bit 5 of the version field.
    ///
    /// # Returns
    /// true if vote expand flag is set, false otherwise
    ///
    /// # Examples
    /// ```
    /// use common_types::common::blocks::BlockVersion;
    ///
    /// let version = BlockVersion::new(1, 4, false, true);
    /// assert_eq!(version.vote_expand_flag(), true);
    ///
    /// let version = BlockVersion::new(1, 4, false, false);
    /// assert_eq!(version.vote_expand_flag(), false);
    /// ```
    pub fn vote_expand_flag(&self) -> bool {
        (self.0 & Self::VOTE_EXPAND_MASK) != 0
    }
    
    /// Extract the base version number.
    ///
    /// The base version is stored in bits 6-31 of the version field.
    ///
    /// # Returns
    /// Base version number (0-67,108,863)
    ///
    /// # Examples
    /// ```
    /// use common_types::common::blocks::BlockVersion;
    ///
    /// let version = BlockVersion::new(1, 4, false, false);
    /// assert_eq!(version.base_version(), 1);
    ///
    /// let version = BlockVersion::new(2, 8, false, false);
    /// assert_eq!(version.base_version(), 2);
    /// ```
    pub fn base_version(&self) -> u32 {
        (self.0 & Self::VERSION_MASK) >> Self::VERSION_SHIFT
    }
    
    /// Calculate the maximum number of shards for this version's s value.
    ///
    /// Formula: 2^s - 1 (value 0 is reserved)
    ///
    /// # Returns
    /// Maximum number of shards (0 for s=0, up to 32767 for s=15)
    ///
    /// # Examples
    /// ```
    /// use common_types::common::blocks::BlockVersion;
    ///
    /// let version = BlockVersion::new(1, 0, false, false);
    /// assert_eq!(version.max_shards(), 0); // No sharding
    ///
    /// let version = BlockVersion::new(1, 4, false, false);
    /// assert_eq!(version.max_shards(), 15); // 2^4 - 1
    ///
    /// let version = BlockVersion::new(1, 8, false, false);
    /// assert_eq!(version.max_shards(), 255); // 2^8 - 1
    /// ```
    pub fn max_shards(&self) -> u32 {
        let s = self.s();
        if s == 0 {
            0
        } else {
            (1u32 << s) - 1
        }
    }
    
    /// Set a new s value, keeping other fields unchanged.
    ///
    /// # Arguments
    /// * `s` - New hash-sorting number (0-15)
    ///
    /// # Panics
    /// Panics if s > 15
    ///
    /// # Examples
    /// ```
    /// use common_types::common::blocks::BlockVersion;
    ///
    /// let mut version = BlockVersion::new(1, 4, false, false);
    /// version.set_s(8);
    /// assert_eq!(version.s(), 8);
    /// assert_eq!(version.base_version(), 1); // Unchanged
    /// assert_eq!(version.vote_k_flag(), false); // Unchanged
    /// ```
    pub fn set_s(&mut self, s: u8) {
        assert!(s <= 15, "s must be 0-15 (4 bits), got {}", s);
        
        // Clear s bits and set new value
        self.0 = (self.0 & !Self::S_MASK) | ((s as u32) & Self::S_MASK);
    }
    
    /// Set the Vote K flag, keeping other fields unchanged.
    ///
    /// # Arguments
    /// * `vote_k` - New vote k flag value
    ///
    /// # Examples
    /// ```
    /// use common_types::common::blocks::BlockVersion;
    ///
    /// let mut version = BlockVersion::new(1, 4, false, false);
    /// version.set_vote_k_flag(true);
    /// assert_eq!(version.vote_k_flag(), true);
    /// assert_eq!(version.s(), 4); // Unchanged
    /// ```
    pub fn set_vote_k_flag(&mut self, vote_k: bool) {
        if vote_k {
            self.0 |= Self::VOTE_K_MASK;
        } else {
            self.0 &= !Self::VOTE_K_MASK;
        }
    }
    
    /// Set the Vote Expand flag, keeping other fields unchanged.
    ///
    /// # Arguments
    /// * `vote_expand` - New vote expand flag value
    ///
    /// # Examples
    /// ```
    /// use common_types::common::blocks::BlockVersion;
    ///
    /// let mut version = BlockVersion::new(1, 4, false, false);
    /// version.set_vote_expand_flag(true);
    /// assert_eq!(version.vote_expand_flag(), true);
    /// assert_eq!(version.s(), 4); // Unchanged
    /// ```
    pub fn set_vote_expand_flag(&mut self, vote_expand: bool) {
        if vote_expand {
            self.0 |= Self::VOTE_EXPAND_MASK;
        } else {
            self.0 &= !Self::VOTE_EXPAND_MASK;
        }
    }
    
    /// Set a new base version, keeping other fields unchanged.
    ///
    /// # Arguments
    /// * `base_version` - New base version number
    ///
    /// # Examples
    /// ```
    /// use common_types::common::blocks::BlockVersion;
    ///
    /// let mut version = BlockVersion::new(1, 4, false, false);
    /// version.set_base_version(2);
    /// assert_eq!(version.base_version(), 2);
    /// assert_eq!(version.s(), 4); // Unchanged
    /// assert_eq!(version.vote_k_flag(), false); // Unchanged
    /// ```
    pub fn set_base_version(&mut self, base_version: u32) {
        let base = (base_version & (Self::VERSION_MASK >> Self::VERSION_SHIFT)) << Self::VERSION_SHIFT;
        self.0 = base | (self.0 & !Self::VERSION_MASK);
    }
}

// Implement From/Into for backward compatibility with u32
impl From<u32> for BlockVersion {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl From<BlockVersion> for u32 {
    fn from(version: BlockVersion) -> Self {
        version.as_u32()
    }
}

impl fmt::Display for BlockVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "v{}.s{}.vk{}.ve{} (0x{:08x})",
            self.base_version(),
            self.s(),
            if self.vote_k_flag() { "1" } else { "0" },
            if self.vote_expand_flag() { "1" } else { "0" },
            self.0
        )
    }
}

impl Default for BlockVersion {
    /// Default version: v1 with s=4 (15 shards), no votes
    fn default() -> Self {
        Self::new(1, 4, false, false)
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Extract hash-sorting number from a raw u32 version value.
///
/// This is a convenience function for working with legacy code that
/// uses u32 directly instead of BlockVersion.
///
/// # Examples
/// ```
/// use common_types::common::blocks::extract_s_from_version;
///
/// let version: u32 = 0x00000044; // v1, s=4
/// assert_eq!(extract_s_from_version(version), 4);
/// ```
pub fn extract_s_from_version(version: u32) -> u8 {
    BlockVersion::from_u32(version).s()
}

/// Extract Vote K flag from a raw u32 version value.
///
/// # Examples
/// ```
/// use common_types::common::blocks::extract_vote_k_from_version;
///
/// let version: u32 = 0x00000054; // v1, s=4, vote_k=1
/// assert_eq!(extract_vote_k_from_version(version), true);
/// ```
pub fn extract_vote_k_from_version(version: u32) -> bool {
    BlockVersion::from_u32(version).vote_k_flag()
}

/// Extract Vote Expand flag from a raw u32 version value.
///
/// # Examples
/// ```
/// use common_types::common::blocks::extract_vote_expand_from_version;
///
/// let version: u32 = 0x00000064; // v1, s=4, vote_expand=1
/// assert_eq!(extract_vote_expand_from_version(version), true);
/// ```
pub fn extract_vote_expand_from_version(version: u32) -> bool {
    BlockVersion::from_u32(version).vote_expand_flag()
}

/// Extract base version from a raw u32 version value.
///
/// This is a convenience function for working with legacy code.
///
/// # Examples
/// ```
/// use common_types::common::blocks::extract_base_version;
///
/// let version: u32 = 0x00000044; // v1, s=4
/// assert_eq!(extract_base_version(version), 1);
/// ```
pub fn extract_base_version(version: u32) -> u32 {
    BlockVersion::from_u32(version).base_version()
}

/// Create a version u32 from base version, s value, and vote flags.
///
/// This is a convenience function for working with legacy code.
///
/// # Examples
/// ```
/// use common_types::common::blocks::make_version;
///
/// let version = make_version(1, 4, false, false);
/// assert_eq!(version, 0x00000044);
/// ```
pub fn make_version(base_version: u32, s: u8, vote_k: bool, vote_expand: bool) -> u32 {
    BlockVersion::new(base_version, s, vote_k, vote_expand).as_u32()
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_version_creation() {
        let version = BlockVersion::new(1, 4, false, false);
        assert_eq!(version.base_version(), 1);
        assert_eq!(version.s(), 4);
        assert_eq!(version.vote_k_flag(), false);
        assert_eq!(version.vote_expand_flag(), false);
        assert_eq!(version.as_u32(), 0x00000044); // (1 << 6) | 4 = 0x44
    }
    
    #[test]
    fn test_version_with_votes() {
        let version = BlockVersion::new(1, 4, true, false);
        assert_eq!(version.vote_k_flag(), true);
        assert_eq!(version.vote_expand_flag(), false);
        assert_eq!(version.as_u32(), 0x00000054); // (1 << 6) | (1 << 4) | 4 = 0x54
        
        let version = BlockVersion::new(1, 4, false, true);
        assert_eq!(version.vote_k_flag(), false);
        assert_eq!(version.vote_expand_flag(), true);
        assert_eq!(version.as_u32(), 0x00000064); // (1 << 6) | (1 << 5) | 4 = 0x64
        
        let version = BlockVersion::new(1, 4, true, true);
        assert_eq!(version.vote_k_flag(), true);
        assert_eq!(version.vote_expand_flag(), true);
        assert_eq!(version.as_u32(), 0x00000074); // (1 << 6) | (1 << 5) | (1 << 4) | 4 = 0x74
    }
    
    #[test]
    fn test_version_zero_s() {
        let version = BlockVersion::new(1, 0, false, false);
        assert_eq!(version.base_version(), 1);
        assert_eq!(version.s(), 0);
        assert_eq!(version.as_u32(), 0x00000040); // (1 << 6) = 0x40
    }
    
    #[test]
    fn test_version_max_s() {
        let version = BlockVersion::new(1, 15, false, false);
        assert_eq!(version.base_version(), 1);
        assert_eq!(version.s(), 15);
        assert_eq!(version.as_u32(), 0x0000004F); // (1 << 6) | 15 = 0x4F
    }
    
    #[test]
    #[should_panic(expected = "s must be 0-15")]
    fn test_version_invalid_s() {
        BlockVersion::new(1, 16, false, false); // Should panic
    }
    
    #[test]
    fn test_version_from_u32() {
        let version = BlockVersion::from_u32(0x00000044);
        assert_eq!(version.base_version(), 1);
        assert_eq!(version.s(), 4);
        assert_eq!(version.vote_k_flag(), false);
        assert_eq!(version.vote_expand_flag(), false);
    }
    
    #[test]
    fn test_version_roundtrip() {
        let original = BlockVersion::new(2, 8, true, true);
        let raw = original.as_u32();
        let restored = BlockVersion::from_u32(raw);
        assert_eq!(original, restored);
    }
    
    #[test]
    fn test_max_shards() {
        assert_eq!(BlockVersion::new(1, 0, false, false).max_shards(), 0);
        assert_eq!(BlockVersion::new(1, 4, false, false).max_shards(), 15);
        assert_eq!(BlockVersion::new(1, 8, false, false).max_shards(), 255);
        assert_eq!(BlockVersion::new(1, 12, false, false).max_shards(), 4095);
        assert_eq!(BlockVersion::new(1, 15, false, false).max_shards(), 32767);
    }
    
    #[test]
    fn test_set_s() {
        let mut version = BlockVersion::new(1, 4, true, true);
        version.set_s(8);
        assert_eq!(version.s(), 8);
        assert_eq!(version.base_version(), 1); // Unchanged
        assert_eq!(version.vote_k_flag(), true); // Unchanged
        assert_eq!(version.vote_expand_flag(), true); // Unchanged
    }
    
    #[test]
    fn test_set_vote_flags() {
        let mut version = BlockVersion::new(1, 4, false, false);
        
        version.set_vote_k_flag(true);
        assert_eq!(version.vote_k_flag(), true);
        assert_eq!(version.s(), 4); // Unchanged
        assert_eq!(version.vote_expand_flag(), false); // Unchanged
        
        version.set_vote_expand_flag(true);
        assert_eq!(version.vote_expand_flag(), true);
        assert_eq!(version.vote_k_flag(), true); // Still true
        assert_eq!(version.s(), 4); // Unchanged
    }
    
    #[test]
    fn test_set_base_version() {
        let mut version = BlockVersion::new(1, 4, true, true);
        version.set_base_version(2);
        assert_eq!(version.base_version(), 2);
        assert_eq!(version.s(), 4); // Unchanged
        assert_eq!(version.vote_k_flag(), true); // Unchanged
        assert_eq!(version.vote_expand_flag(), true); // Unchanged
    }
    
    #[test]
    fn test_helper_functions() {
        let version = make_version(1, 4, true, false);
        assert_eq!(version, 0x00000054);
        assert_eq!(extract_s_from_version(version), 4);
        assert_eq!(extract_vote_k_from_version(version), true);
        assert_eq!(extract_vote_expand_from_version(version), false);
        assert_eq!(extract_base_version(version), 1);
    }
    
    #[test]
    fn test_display() {
        let version = BlockVersion::new(1, 4, true, false);
        let display = format!("{}", version);
        assert!(display.contains("v1"));
        assert!(display.contains("s4"));
        assert!(display.contains("vk1"));
        assert!(display.contains("ve0"));
    }
    
    #[test]
    fn test_default() {
        let version = BlockVersion::default();
        assert_eq!(version.base_version(), 1);
        assert_eq!(version.s(), 4);
        assert_eq!(version.vote_k_flag(), false);
        assert_eq!(version.vote_expand_flag(), false);
    }
    
    #[test]
    fn test_bit_calculation_explicit() {
        // Verify bit calculation step by step for clarity
        let base_version = 10u32;
        let s = 8u8;
        let vote_k = true;
        let vote_expand = true;
        
        // Calculate expected value manually
        let base_bits = base_version << 6;        // 10 << 6 = 640 (0x280)
        let s_bits = s as u32;                    // 8 = 0x08
        let vote_k_bits = if vote_k { 16 } else { 0 };      // bit 4 = 16 (0x10)
        let vote_expand_bits = if vote_expand { 32 } else { 0 }; // bit 5 = 32 (0x20)
        
        let expected = base_bits | s_bits | vote_k_bits | vote_expand_bits;
        // 640 | 8 | 16 | 32 = 696 (0x2B8)
        
        assert_eq!(expected, 696);
        assert_eq!(expected, 0x2B8);
        
        // Verify BlockVersion produces the same result
        let version = BlockVersion::new(base_version, s, vote_k, vote_expand);
        assert_eq!(version.as_u32(), expected);
        assert_eq!(version.as_u32(), 0x2B8);
    }
    
    #[test]
    fn test_various_versions() {
        // Test a variety of version/s/vote combinations
        let test_cases = vec![
            (1, 0, false, false, 0x00000040),  // (1 << 6) = 64 = 0x40
            (1, 4, false, false, 0x00000044),  // (1 << 6) | 4 = 68 = 0x44
            (1, 4, true, false, 0x00000054),   // (1 << 6) | 16 | 4 = 84 = 0x54
            (1, 4, false, true, 0x00000064),   // (1 << 6) | 32 | 4 = 100 = 0x64
            (1, 4, true, true, 0x00000074),    // (1 << 6) | 48 | 4 = 116 = 0x74
            (1, 8, false, false, 0x00000048),  // (1 << 6) | 8 = 72 = 0x48
            (1, 15, false, false, 0x0000004F), // (1 << 6) | 15 = 79 = 0x4F
            (2, 4, false, false, 0x00000084),  // (2 << 6) | 4 = 132 = 0x84
            (10, 8, true, true, 0x000002B8),   // (10 << 6) | 48 | 8 = 696 = 0x2B8
        ];
        
        for (base, s, vk, ve, expected_raw) in test_cases {
            let version = BlockVersion::new(base, s, vk, ve);
            assert_eq!(version.base_version(), base, "base mismatch for ({}, {}, {}, {})", base, s, vk, ve);
            assert_eq!(version.s(), s, "s mismatch for ({}, {}, {}, {})", base, s, vk, ve);
            assert_eq!(version.vote_k_flag(), vk, "vk mismatch for ({}, {}, {}, {})", base, s, vk, ve);
            assert_eq!(version.vote_expand_flag(), ve, "ve mismatch for ({}, {}, {}, {})", base, s, vk, ve);
            assert_eq!(version.as_u32(), expected_raw, "raw value mismatch for ({}, {}, {}, {})", base, s, vk, ve);
        }
    }
    
    #[test]
    fn test_bit_field_independence() {
        // Verify that all bit fields are truly independent
        let mut version = BlockVersion::new(0, 15, true, true);
        assert_eq!(version.base_version(), 0);
        assert_eq!(version.s(), 15);
        assert_eq!(version.vote_k_flag(), true);
        assert_eq!(version.vote_expand_flag(), true);
        
        // Change version, others should stay
        version.set_base_version(100);
        assert_eq!(version.base_version(), 100);
        assert_eq!(version.s(), 15);
        assert_eq!(version.vote_k_flag(), true);
        assert_eq!(version.vote_expand_flag(), true);
        
        // Change s, others should stay
        version.set_s(0);
        assert_eq!(version.base_version(), 100);
        assert_eq!(version.s(), 0);
        assert_eq!(version.vote_k_flag(), true);
        assert_eq!(version.vote_expand_flag(), true);
        
        // Change votes, others should stay
        version.set_vote_k_flag(false);
        assert_eq!(version.base_version(), 100);
        assert_eq!(version.s(), 0);
        assert_eq!(version.vote_k_flag(), false);
        assert_eq!(version.vote_expand_flag(), true);
        
        version.set_vote_expand_flag(false);
        assert_eq!(version.base_version(), 100);
        assert_eq!(version.s(), 0);
        assert_eq!(version.vote_k_flag(), false);
        assert_eq!(version.vote_expand_flag(), false);
    }
}