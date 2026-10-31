// examples/version_field_usage.rs
//
// Examples showing how to use the BlockVersion field in beacon headers.
//
// This demonstrates:
// 1. Creating beacon headers with version fields
// 2. Extracting k values from versions
// 3. Validating version fields
// 4. Migrating from raw u32 to BlockVersion

use common::blocks::{BlockVersion, BeaconBlockCandidateHeader};

/// Example 1: Creating a new beacon block with version field
fn example_create_beacon_block() {
    // Create version with base version 1 and k=4 (15 shards)
    let version = BlockVersion::new(1, 4);
    
    println!("Created version: {}", version);
    println!("  Base version: {}", version.base_version());
    println!("  K value: {}", version.k());
    println!("  Max shards: {}", version.max_shards());
    println!("  Raw u32: 0x{:08x}", version.as_u32());
    
    // Use in beacon header
    let header = BeaconBlockCandidateHeader::new(
        version.as_u32(),  // Pass as u32 for compatibility
        1704067200,        // timestamp
        0,                 // height
        1000,              // difficulty
        0x1d00ffff,        // bits
        [0u8; 32],         // prev_block_hash
        [0u8; 32],         // prev_mmr_root
        [0u8; 32],         // merkle_root
        [0u8; 32],         // merged_mining_root
    );
    
    println!("\nBeacon header created with version field");
}

/// Example 2: Extracting k value from existing header
fn example_extract_k_from_header(header: &BeaconBlockCandidateHeader) {
    // Method 1: Using BlockVersion wrapper
    let version = BlockVersion::from_u32(header.version);
    let k = version.k();
    
    println!("Extracted k={} from header version", k);
    
    // Method 2: Using helper function (for legacy code)
    let k2 = extract_k_from_version(header.version);
    assert_eq!(k, k2);
    
    println!("Both methods agree: k={}", k);
}

/// Example 3: Different k values for different network sizes
fn example_network_configurations() {
    println!("\nNetwork configurations with different k values:\n");
    
    // Small network: k=4 (15 shards)
    let small = BlockVersion::new(1, 4);
    println!("Small network (k=4):");
    println!("  Max shards: {}", small.max_shards());
    println!("  Version: {}", small);
    
    // Medium network: k=8 (255 shards)
    let medium = BlockVersion::new(1, 8);
    println!("\nMedium network (k=8):");
    println!("  Max shards: {}", medium.max_shards());
    println!("  Version: {}", medium);
    
    // Large network: k=12 (4095 shards)
    let large = BlockVersion::new(1, 12);
    println!("\nLarge network (k=12):");
    println!("  Max shards: {}", large.max_shards());
    println!("  Version: {}", large);
    
    // Maximum: k=15 (32767 shards)
    let maximum = BlockVersion::new(1, 15);
    println!("\nMaximum network (k=15):");
    println!("  Max shards: {}", maximum.max_shards());
    println!("  Version: {}", maximum);
}

/// Example 4: Version upgrades while preserving k
fn example_version_upgrade() {
    println!("\nVersion upgrade example:\n");
    
    // Start with v1, k=4
    let mut version = BlockVersion::new(1, 4);
    println!("Original: {}", version);
    
    // Upgrade to v2, keep k=4
    version.set_base_version(2);
    println!("After upgrade: {}", version);
    println!("  K preserved: {}", version.k());
}

/// Example 5: Dynamic k adjustment
fn example_dynamic_k_adjustment() {
    println!("\nDynamic k adjustment:\n");
    
    // Start with k=4 (15 shards)
    let mut version = BlockVersion::new(1, 4);
    println!("Initial: {} ({} shards)", version, version.max_shards());
    
    // Network grows, increase to k=8 (255 shards)
    version.set_k(8);
    println!("After growth: {} ({} shards)", version, version.max_shards());
    
    // Version still v1
    println!("Base version unchanged: {}", version.base_version());
}

/// Example 6: Validation function using k
fn validate_shard_id_against_version(shard_id: u16, header_version: u32) -> Result<(), String> {
    let version = BlockVersion::from_u32(header_version);
    let max_shards = version.max_shards();
    
    if shard_id >= max_shards as u16 {
        return Err(format!(
            "Shard ID {} exceeds maximum {} for k={}",
            shard_id,
            max_shards,
            version.k()
        ));
    }
    
    Ok(())
}

/// Example 7: Mining pool configuration
fn example_mining_pool_config() {
    println!("\nMining pool configurations:\n");
    
    // Pool mining (any shard): k=0
    let pool_version = BlockVersion::new(1, 0);
    println!("Pool mining: {}", pool_version);
    println!("  Shards: none (pool distributes work)");
    
    // Solo mining specific shard: k=4
    let solo_version = BlockVersion::new(1, 4);
    println!("\nSolo mining: {}", solo_version);
    println!("  Target shard must match hash-sorting");
    
    // The k value determines difficulty multiplier
    let k = solo_version.k();
    let difficulty_multiplier = 1u32 << k; // 2^k
    println!("  Difficulty multiplier: {}x", difficulty_multiplier);
}

/// Example 8: Serialization/Deserialization
fn example_serialization() {
    use serde_json;
    
    println!("\nSerialization example:\n");
    
    let version = BlockVersion::new(1, 4);
    
    // Serialize as u32 (backward compatible)
    let json = serde_json::to_string(&version.as_u32()).unwrap();
    println!("Serialized: {}", json);
    
    // Deserialize
    let raw: u32 = serde_json::from_str(&json).unwrap();
    let restored = BlockVersion::from_u32(raw);
    
    println!("Restored: {}", restored);
    assert_eq!(version, restored);
}

/// Example 9: Backward compatibility
fn example_backward_compatibility() {
    println!("\nBackward compatibility:\n");
    
    // Legacy code using raw u32
    let legacy_version: u32 = 0x00000014; // v1, k=4 in old format
    
    // New code can extract k
    let k = extract_k_from_version(legacy_version);
    let base = extract_base_version(legacy_version);
    
    println!("Legacy version: 0x{:08x}", legacy_version);
    println!("  Extracted base: {}", base);
    println!("  Extracted k: {}", k);
    
    // Can also wrap in BlockVersion for full functionality
    let version = BlockVersion::from_u32(legacy_version);
    println!("  As BlockVersion: {}", version);
}

/// Example 10: Fork detection using version
fn example_fork_detection() {
    println!("\nFork detection with version:\n");
    
    // Chain A: v1, k=4
    let chain_a = BlockVersion::new(1, 4);
    
    // Chain B: v1, k=8 (different k = incompatible)
    let chain_b = BlockVersion::new(1, 8);
    
    // Chain C: v2, k=4 (upgraded version, same k)
    let chain_c = BlockVersion::new(2, 4);
    
    println!("Chain A: {} (compatible baseline)", chain_a);
    println!("Chain B: {} (INCOMPATIBLE - different k!)", chain_b);
    println!("Chain C: {} (compatible - same k)", chain_c);
    
    // Check compatibility
    if chain_a.k() == chain_b.k() {
        println!("✓ A and B can merge (same k)");
    } else {
        println!("✗ A and B cannot merge (different k)");
    }
    
    if chain_a.k() == chain_c.k() {
        println!("✓ A and C can merge (same k)");
    } else {
        println!("✗ A and C cannot merge (different k)");
    }
}

fn main() {
    println!("=".repeat(70));
    println!("BlockVersion Field Usage Examples");
    println!("=".repeat(70));
    
    example_create_beacon_block();
    println!("\n{}", "=".repeat(70));
    
    example_network_configurations();
    println!("\n{}", "=".repeat(70));
    
    example_version_upgrade();
    println!("\n{}", "=".repeat(70));
    
    example_dynamic_k_adjustment();
    println!("\n{}", "=".repeat(70));
    
    example_mining_pool_config();
    println!("\n{}", "=".repeat(70));
    
    example_serialization();
    println!("\n{}", "=".repeat(70));
    
    example_backward_compatibility();
    println!("\n{}", "=".repeat(70));
    
    example_fork_detection();
    println!("\n{}", "=".repeat(70));
}
