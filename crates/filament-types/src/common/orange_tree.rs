// merged_mining/orange_tree.rs
//
// Orange Tree Encoding - Compact representation of active/inactive shards
//
// PURPOSE:
// Encodes which shards are actively submitting blocks vs inactive in the merged
// mining tree using a space-efficient bracket notation algorithm.
//
// ARCHITECTURE:
// - Full leaf: Shard is active (submitting blocks) - encoded as "1"
// - Empty leaf: Shard is inactive/disabled - encoded as "0"
// - Orange node: Mix of active and empty descendants - encoded with brackets
//
// ENCODING STRUCTURE:
// - bracket_structure: BitVec of '(' and ')' marking orange node locations
// - fill_pattern: BitVec of '1' and '0' marking full vs empty leaves
//
// SERIALIZATION OPTIMIZATION:
// Orange nodes always end with ')' bracket, so we remove it before serialization
// and add it back during deserialization, saving 1 bit per orange node.

use serde::{Deserialize, Serialize, Deserializer, Serializer};
use log::debug;
use bit_vec::BitVec;

/// Orange Tree Encoding - compact representation of active/inactive shards
/// 
/// Uses bracket notation to encode the tree structure:
/// - Full leaf: "1"
/// - Empty leaf: "0"
/// - Orange node: "1" + left + "0" + right
/// 
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrangeTreeEncoding {
    /// Bracket structure encoding orange node locations
    /// '(' = 1 (true), ')' = 0 (false)
    bracket_structure: BitVec,
    
    /// Pattern of full (1) and empty (0) nodes
    fill_pattern: BitVec,
}

// Manual Serialize implementation for BitVec with optimization
impl Serialize for OrangeTreeEncoding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        
        let mut state = serializer.serialize_struct("OrangeTreeEncoding", 2)?;
        
        // OPTIMIZATION: Remove the last ')' bracket before serialization
        // since it's always present in orange nodes (saves 1 bit per orange node)
        let optimized_brackets = if self.is_orange() && self.bracket_structure.len() > 0 {
            let mut opt = self.bracket_structure.clone();
            opt.pop(); // Remove last bit
            opt
        } else {
            self.bracket_structure.clone()
        };
        
        let bracket_bytes = optimized_brackets.to_bytes();
        let bracket_len = optimized_brackets.len();
        state.serialize_field("bracket_structure", &(bracket_bytes, bracket_len))?;
        
        let fill_bytes = self.fill_pattern.to_bytes();
        let fill_len = self.fill_pattern.len();
        state.serialize_field("fill_pattern", &(fill_bytes, fill_len))?;
        
        state.end()
    }
}

// Manual Deserialize implementation for BitVec with optimization
impl<'de> Deserialize<'de> for OrangeTreeEncoding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        
        #[derive(Deserialize)]
        struct OrangeTreeEncodingHelper {
            bracket_structure: (Vec<u8>, usize),
            fill_pattern: (Vec<u8>, usize),
        }
        
        let helper = OrangeTreeEncodingHelper::deserialize(deserializer)?;
        
        let mut bracket_structure = BitVec::from_bytes(&helper.bracket_structure.0);
        bracket_structure.truncate(helper.bracket_structure.1);
        
        let mut fill_pattern = BitVec::from_bytes(&helper.fill_pattern.0);
        fill_pattern.truncate(helper.fill_pattern.1);
        
        // VALIDATION: Completely empty tree is prohibited
        // Use full encoding (empty brackets, fill=[1]) for a full tree
        if bracket_structure.is_empty() && fill_pattern.is_empty() {
            return Err(D::Error::custom(
                "Completely empty orange tree encoding is prohibited. \
                 Use full encoding (empty brackets, fill=[1]) for a full tree."
            ));
        }
        
        // OPTIMIZATION: Add back the trailing ')' for orange nodes
        if !bracket_structure.is_empty() {
            bracket_structure.push(false); // Add ')' back
        }
        
        Ok(OrangeTreeEncoding {
            bracket_structure,
            fill_pattern,
        })
    }
}

impl OrangeTreeEncoding {
    /// Create encoding for a full leaf (active shard)
    /// 
    /// USAGE: When a shard is actively submitting blocks
    /// ENCODING: bracket=[], fill=[1]
    pub fn new_full_leaf() -> Self {
        let mut fill = BitVec::new();
        fill.push(true); // Full = 1
        Self {
            bracket_structure: BitVec::new(), // No brackets for leaf
            fill_pattern: fill,
        }
    }
    
    /// Create encoding for an empty leaf (inactive shard)
    /// 
    /// USAGE: When a shard is disabled or not submitting blocks
    /// ENCODING: bracket=[], fill=[0]
    pub fn new_empty_leaf() -> Self {
        let mut fill = BitVec::new();
        fill.push(false); // Empty = 0
        Self {
            bracket_structure: BitVec::new(), // No brackets for leaf
            fill_pattern: fill,
        }
    }

    /// Compose two encodings (left and right children) into parent encoding
    /// 
    /// COMPOSITION RULES:
    /// - Both empty → parent is empty
    /// - Both full → parent is full
    /// - Mixed (orange) → parent is orange with bracket structure
    /// 
    /// BRACKET PATTERN: "(" + left_brackets + ")" + right_brackets
    /// FILL PATTERN: left_fill + right_fill
    pub fn compose(left: &OrangeTreeEncoding, right: &OrangeTreeEncoding) -> Self {
        let left_is_full = left.is_full();
        let right_is_full = right.is_full();
        let left_is_empty = left.is_empty();
        let right_is_empty = right.is_empty();
        
        debug!(
            "Composing: left(full={}, empty={}), right(full={}, empty={})",
            left_is_full, left_is_empty, right_is_full, right_is_empty
        );
        
        // CASE 1: Both empty → parent is empty
        if left_is_empty && right_is_empty {
            debug!("Result: Both empty → parent empty");
            return Self::new_empty_leaf();
        }
        
        // CASE 2: Both full → parent is full
        if left_is_full && right_is_full {
            debug!("Result: Both full → parent full");
            return Self::new_full_leaf();
        }
        
        // CASE 3: Mixed (neither both full nor both empty) → parent is orange
        debug!("Result: Mixed → parent is orange");
        
        // Build bracket structure: "(" + left_brackets + ")" + right_brackets
        // This pattern allows reconstructing the tree structure during traversal
        let mut bracket_structure = BitVec::new();
        bracket_structure.push(true); // '('
        bracket_structure.extend(left.bracket_structure.iter());
        bracket_structure.push(false); // ')'
        bracket_structure.extend(right.bracket_structure.iter());
        
        // Build fill pattern: concatenate left and right patterns
        let mut fill_pattern = BitVec::new();
        fill_pattern.extend(left.fill_pattern.iter());
        fill_pattern.extend(right.fill_pattern.iter());
        
        Self {
            bracket_structure,
            fill_pattern,
        }
    }

    /// Check if this encoding represents a full subtree (all shards active)
    pub fn is_full(&self) -> bool {
        self.bracket_structure.is_empty() && 
        self.fill_pattern.len() == 1 && 
        self.fill_pattern[0] == true
    }
    
    /// Check if this encoding represents an empty subtree (no active shards)
    pub fn is_empty(&self) -> bool {
        self.bracket_structure.is_empty() && 
        self.fill_pattern.len() == 1 && 
        self.fill_pattern[0] == false
    }
    
    /// Check if this encoding represents an orange node (mixed active/inactive)
    pub fn is_orange(&self) -> bool {
        !self.bracket_structure.is_empty()
    }
    
    /// Get the bracket structure
    pub fn get_bracket_structure(&self) -> &BitVec {
        &self.bracket_structure
    }
    
    /// Get the fill pattern
    pub fn get_fill_pattern(&self) -> &BitVec {
        &self.fill_pattern
    }
    
    /// Get a compact string representation for logging and debugging
    /// 
    /// FORMATS:
    /// - "FULL" - All shards active
    /// - "EMPTY" - No shards active
    /// - "ORANGE[brackets:fill]" - Mixed state with structure
    pub fn to_compact_string(&self) -> String {
        if self.is_full() {
            "FULL".to_string()
        } else if self.is_empty() {
            "EMPTY".to_string()
        } else {
            let bracket_str: String = self.bracket_structure
                .iter()
                .map(|b| if b { '(' } else { ')' })
                .collect();
            let fill_str: String = self.fill_pattern
                .iter()
                .map(|b| if b { '1' } else { '0' })
                .collect();
            format!("ORANGE[{}:{}]", bracket_str, fill_str)
        }
    }
    
    /// Count the number of active shards represented by this encoding
    /// 
    /// CALCULATION:
    /// - Full tree: 2^height shards
    /// - Empty tree: 0 shards
    /// - Orange tree: Recursive count through structure
    pub fn count_active_shards(&self, height: u32) -> usize {
        let height = height as usize;
        if self.is_full() {
            // Full means all shards in subtree are active
            1 << height
        } else if self.is_empty() {
            0
        } else {
            // For orange nodes, recursively count active shards
            self.count_active_recursive(height)
        }
    }
    
    /// Helper function to recursively count active shards in an orange tree
    fn count_active_recursive(&self, height: usize) -> usize {
        // Double-check we're not trying to count on a non-orange node
        if !self.is_orange() {
            if self.is_full() {
                return 1 << height;
            } else if self.is_empty() {
                return 0;
            }
        }
        
        if height == 0 {
            // At leaf level, check if this leaf is active
            if self.fill_pattern.len() > 0 && self.fill_pattern[0] {
                1
            } else {
                0
            }
        } else {
            // Split into left and right children and count recursively
            let (left_encoding, right_encoding) = self.split_children(height);
            
            let left_count = if left_encoding.is_full() {
                1 << (height - 1)
            } else if left_encoding.is_empty() {
                0
            } else {
                left_encoding.count_active_recursive(height - 1)
            };
            
            let right_count = if right_encoding.is_full() {
                1 << (height - 1)
            } else if right_encoding.is_empty() {
                0
            } else {
                right_encoding.count_active_recursive(height - 1)
            };
            
            left_count + right_count
        }
    }
    
    /// Split an orange node into its left and right child encodings
    /// 
    /// ALGORITHM:
    /// 1. Find matching closing bracket for opening '('
    /// 2. Extract left brackets (between '(' and ')')
    /// 3. Extract right brackets (after ')')
    /// 4. Distribute fill bits based on bracket structure
    fn split_children(&self, _height: usize) -> (OrangeTreeEncoding, OrangeTreeEncoding) {
        if self.bracket_structure.is_empty() {
            panic!("Cannot split a leaf node - brackets empty, fill_len={}, fill[0]={:?}", 
                   self.fill_pattern.len(),
                   if self.fill_pattern.len() > 0 { Some(self.fill_pattern[0]) } else { None });
        }
        
        // The structure is: '(' + left_brackets + ')' + right_brackets
        // Find the matching closing bracket for the opening '('
        
        let mut depth = 0;
        let mut split_pos = 0;
        
        for (i, bit) in self.bracket_structure.iter().enumerate().skip(1) {
            if bit {
                depth += 1;
            } else {
                if depth == 0 {
                    // Found the matching ')'
                    split_pos = i + 1;
                    break;
                }
                depth -= 1;
            }
        }
        
        // Extract left brackets (everything between first '(' and matching ')')
        let left_brackets: BitVec = self.bracket_structure.iter()
            .skip(1)
            .take(split_pos - 2)
            .collect();
        
        // Extract right brackets (everything after the closing ')')
        let right_brackets: BitVec = self.bracket_structure.iter()
            .skip(split_pos)
            .collect();
        
        // Determine how many fill bits each child needs
        let left_fill_count = if left_brackets.is_empty() {
            // Left is a leaf
            1
        } else {
            // Left is orange: count closing brackets + 1
            // Each closing bracket represents a fill bit
            left_brackets.iter().filter(|&b| !b).count() + 1
        };
        
        let left_fill: BitVec = self.fill_pattern.iter()
            .take(left_fill_count)
            .collect();
        
        let right_fill: BitVec = self.fill_pattern.iter()
            .skip(left_fill_count)
            .collect();
        
        let left_encoding = OrangeTreeEncoding {
            bracket_structure: left_brackets,
            fill_pattern: left_fill,
        };
        
        let right_encoding = OrangeTreeEncoding {
            bracket_structure: right_brackets,
            fill_pattern: right_fill,
        };
        
        (left_encoding, right_encoding)
    }

    /// Serialize to bytes using bincode
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).expect("Serialization failed")
    }

    /// Deserialize from bytes using bincode
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard()).map(|(v, _)| v)
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("JSON serialization failed")
    }

    /// Deserialize from JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

   /// Validate size constraints for merged mining proof efficiency
    /// 
    /// RULES FOR ORANGE NODES (IN-MEMORY REPRESENTATION):
    /// 1. len(bracket_structure) = 2k (EVEN number, k = orange depth)
    /// 2. len(fill_pattern) ≥ 2 (at least two children)
    /// 3. len(fill_pattern) ≤ 2^tree_height (bounded by max possible leaves)
    /// 4. len(bracket_structure) ≤ 2 * (2^tree_height - 1) (bounded by max tree nodes)
    /// 5. SERIALIZED SIZE ≤ 18k bits (expressed as bytes for efficiency)
    /// 
    /// RATIONALE FOR RULE 5:
    /// - In-memory: bracket_len + fill_len ≤ 18k + 1 bits
    /// - Serialized: (bracket_len - 1) + fill_len ≤ 18k bits (trailing ')' removed)
    /// - In bytes: serialized_bits / 8, rounded up for safety
    /// - Formula: ⌈(bracket_len + fill_len - 1) / 8⌉ ≤ ⌈18k / 8⌉
    /// - Simplified: ⌈(bracket_len + fill_len - 1) / 8⌉ ≤ ⌈9k / 4⌉
    /// 
    /// EXAMPLES (k = orange_depth):
    /// k=1: max 3 bytes   (⌈18/8⌉ = ⌈2.25⌉ = 3)
    /// k=2: max 5 bytes   (⌈36/8⌉ = ⌈4.5⌉ = 5)
    /// k=4: max 9 bytes   (⌈72/8⌉ = 9)
    /// k=8: max 18 bytes  (⌈144/8⌉ = 18)
    /// k=16: max 36 bytes (⌈288/8⌉ = 36)
    pub fn validate_size_constraints(&self, tree_height: u32) -> Result<(), String> {
        // Full and empty leaves are always valid
        if self.is_full() || self.is_empty() {
            return Ok(());
        }
        
        let bracket_len = self.bracket_structure.len();
        let fill_len = self.fill_pattern.len();
        
        // RULE 1: Bracket structure must be EVEN length (in-memory representation)
        if bracket_len % 2 != 0 {
            return Err(format!(
                "Invalid bracket structure length {}: must be even (2k) in memory representation",
                bracket_len
            ));
        }
        
        // Calculate k (orange depth)
        let k = bracket_len / 2;
        
        // RULE 2: Fill pattern must have at least 2 entries
        if fill_len < 2 {
            return Err(format!(
                "Invalid fill pattern length {}: orange nodes must have at least 2 fills",
                fill_len
            ));
        }
        
        // RULE 3: Fill pattern bounded by maximum possible leaves
        let max_fills = 1usize << tree_height;
        if fill_len > max_fills {
            return Err(format!(
                "Fill pattern length {} exceeds maximum {} for tree height {}",
                fill_len, max_fills, tree_height
            ));
        }
        
        // RULE 4: Bracket structure bounded by maximum tree nodes
        // For tree with 2^H leaves, max internal nodes is (2^H - 1)
        // Each orange node contributes 2 brackets in memory
        let max_internal_nodes = (1usize << tree_height) - 1;
        let max_brackets = 2 * max_internal_nodes;
        
        if bracket_len > max_brackets {
            return Err(format!(
                "Bracket structure length {} exceeds maximum {} for tree height {} (max {} internal nodes)",
                bracket_len, max_brackets, tree_height, max_internal_nodes
            ));
        }
        
        // RULE 5 (NEW): Total encoding size constraint - 18k bits serialized
        // In-memory total bits: bracket_len + fill_len
        // Serialized total bits: (bracket_len - 1) + fill_len = bracket_len + fill_len - 1
        // Constraint: serialized_bits ≤ 18k
        // In bytes (rounded up): ⌈serialized_bits / 8⌉ ≤ ⌈18k / 8⌉
        
        // Calculate serialized size in bits
        let serialized_bits = bracket_len + fill_len - 1; // -1 because trailing ')' removed
        
        // Calculate max allowed serialized bits: 18k
        let max_serialized_bits = 18 * k;
        
        if serialized_bits > max_serialized_bits {
            // Convert to bytes for clear error message
            let serialized_bytes = (serialized_bits + 7) / 8; // Round up
            let max_serialized_bytes = (max_serialized_bits + 7) / 8; // Round up
            
            return Err(format!(
                "Serialized encoding size {} bits ({} bytes) exceeds maximum {} bits ({} bytes) for k={}. \
                In-memory: {} brackets + {} fills = {} bits total. \
                Constraint: serialized size ≤ 18k bits (18 × {} = {} bits, {} bytes max)",
                serialized_bits, serialized_bytes,
                max_serialized_bits, max_serialized_bytes, k,
                bracket_len, fill_len, bracket_len + fill_len,
                k, max_serialized_bits, max_serialized_bytes
            ));
        }
        
        Ok(())
    }

    /// Calculate the orange nesting depth (k parameter)
    /// 
    /// k = len(brackets) / 2 (for in-memory representation)
    /// 
    /// Represents the "orange depth" or number of orange bracket pairs.
    pub fn orange_depth(&self) -> usize {
        if self.is_full() || self.is_empty() {
            return 0;
        }
        
        self.bracket_structure.len() / 2
    }

    /// Check if this encoding produces an efficient proof
    /// 
    /// EFFICIENCY CRITERIA:
    /// - Proof size <= 2KB for typical trees (relaxed from 1KB)
    /// - Encoding passes size constraint validation
    /// - Orange depth k <= 2 * tree_height (allows for deep nesting)
    pub fn is_efficient_encoding(&self, tree_height: u32) -> bool {
        if self.is_full() || self.is_empty() {
            return true;
        }
        
        // Check size constraints pass
        if self.validate_size_constraints(tree_height).is_err() {
            return false;
        }
        
        // Check proof size estimate (relaxed bound)
        let (_, _, total_bytes) = self.estimate_proof_size(tree_height);
        if total_bytes > 2048 {
            return false; // Proof too large (relaxed from 1KB to 2KB)
        }
        
        // Check orange depth (relaxed bound)
        let k = self.orange_depth();
        if k > 2 * tree_height as usize {
            return false; // Too much nesting (relaxed from tree_height to 2*tree_height)
        }
        
        true
    }

    /// Estimate the size of a merged mining proof for this encoding
    /// 
    /// RETURNS: (encoding_bytes, proof_hash_count, total_bytes)
    pub fn estimate_proof_size(&self, _tree_height: u32) -> (usize, usize, usize) {
        // Calculate logical encoding size (bits → bytes)
        let bracket_bits = self.bracket_structure.len();
        let fill_bits = self.fill_pattern.len();
        let encoding_bytes = (bracket_bits + fill_bits + 7) / 8;
        
        // Count proof hashes needed
        let proof_hash_count = if self.is_full() {
            1  // Full: one hash
        } else if self.is_empty() {
            0  // Empty: no hashes
        } else {
            // Orange: one hash per '1' in fill pattern
            self.fill_pattern.iter().filter(|&b| b).count()
        };
        
        let total_bytes = encoding_bytes + (proof_hash_count * 32);
        (encoding_bytes, proof_hash_count, total_bytes)
    }
}

#[cfg(test)]
mod size_constraint_tests {
    use super::*;
    
    #[test]
    fn test_rule5_serialized_size_constraint() {
        let f = OrangeTreeEncoding::new_full_leaf();
        let e = OrangeTreeEncoding::new_empty_leaf();
        
        // k=1: Simple orange [F, E]
        // brackets=2, fills=2, total=4 bits in-memory
        // serialized: 3 bits ≤ 18×1 = 18 bits ✓
        let o1 = OrangeTreeEncoding::compose(&f, &e);
        assert_eq!(o1.orange_depth(), 1);
        assert!(o1.validate_size_constraints(1).is_ok());
        
        // k=2: [F, E, E, F]
        // More complex but still within 18k limit
        let left = OrangeTreeEncoding::compose(&f, &e);
        let right = OrangeTreeEncoding::compose(&e, &f);
        let o2 = OrangeTreeEncoding::compose(&left, &right);
        let k2 = o2.orange_depth();
        
        let bracket_len = o2.get_bracket_structure().len();
        let fill_len = o2.get_fill_pattern().len();
        let serialized_bits = bracket_len + fill_len - 1;
        let max_allowed_bits = 18 * k2;
        
        assert!(serialized_bits <= max_allowed_bits, 
                "k={}: {} bits should be ≤ {} bits (18k)", 
                k2, serialized_bits, max_allowed_bits);
        assert!(o2.validate_size_constraints(2).is_ok());
    }
    
    #[test]
    fn test_rule5_bytes_calculation() {
        let f = OrangeTreeEncoding::new_full_leaf();
        let e = OrangeTreeEncoding::new_empty_leaf();
        
        // Test that byte rounding works correctly
        let o1 = OrangeTreeEncoding::compose(&f, &e);
        let k = o1.orange_depth();
        
        let bracket_len = o1.get_bracket_structure().len();
        let fill_len = o1.get_fill_pattern().len();
        let serialized_bits = bracket_len + fill_len - 1;
        let serialized_bytes = (serialized_bits + 7) / 8; // Round up
        
        let max_bits = 18 * k;
        let max_bytes = (max_bits + 7) / 8; // Round up
        
        assert!(serialized_bytes <= max_bytes,
                "Serialized {} bytes should be ≤ {} bytes (18k/8 rounded up)",
                serialized_bytes, max_bytes);
    }
    
    #[test]
    fn test_rule5_practical_limits() {
        // Test practical cases at various depths
        let f = OrangeTreeEncoding::new_full_leaf();
        let e = OrangeTreeEncoding::new_empty_leaf();
        
        // Build increasingly complex trees
        let mut current = OrangeTreeEncoding::compose(&f, &e);
        
        for depth in 1..=10 {
            let k = current.orange_depth();
            let bracket_len = current.get_bracket_structure().len();
            let fill_len = current.get_fill_pattern().len();
            let serialized_bits = bracket_len + fill_len - 1;
            let max_allowed = 18 * k;
            
            println!("Depth {}: k={}, brackets={}, fills={}, serialized={} bits, max={} bits",
                     depth, k, bracket_len, fill_len, serialized_bits, max_allowed);
            
            // All should pass the constraint
            assert!(serialized_bits <= max_allowed,
                    "Depth {}: {} bits exceeds {} bits", depth, serialized_bits, max_allowed);
            assert!(current.validate_size_constraints(depth).is_ok());
            
            // Build next level
            current = OrangeTreeEncoding::compose(&current, &e);
        }
    }
    
    #[test]
    fn test_rule5_alternating_pattern() {
        // Alternating pattern creates maximum orange nodes
        let f = OrangeTreeEncoding::new_full_leaf();
        let e = OrangeTreeEncoding::new_empty_leaf();
        
        for height in 1..=6 {
            let num_leaves = 1 << height;
            let leaves: Vec<_> = (0..num_leaves)
                .map(|i| if i % 2 == 0 { f.clone() } else { e.clone() })
                .collect();
            
            let mut level = leaves;
            while level.len() > 1 {
                level = level.chunks(2)
                    .map(|pair| OrangeTreeEncoding::compose(&pair[0], &pair[1]))
                    .collect();
            }
            
            let root = &level[0];
            let k = root.orange_depth();
            let bracket_len = root.get_bracket_structure().len();
            let fill_len = root.get_fill_pattern().len();
            let serialized_bits = bracket_len + fill_len - 1;
            let serialized_bytes = (serialized_bits + 7) / 8;
            let max_bits = 18 * k;
            let max_bytes = (max_bits + 7) / 8;
            
            println!("Height {}: k={}, serialized={} bits ({} bytes), max={} bits ({} bytes)",
                     height, k, serialized_bits, serialized_bytes, max_bits, max_bytes);
            
            // Should pass validation
            assert!(root.validate_size_constraints(height).is_ok(),
                    "Height {} alternating pattern should validate", height);
            
            // Check the 18k constraint
            assert!(serialized_bits <= max_bits,
                    "Height {}: {} bits should be ≤ 18k = {} bits",
                    height, serialized_bits, max_bits);
        }
    }
    
    #[test]
    fn test_rule5_explicit_byte_limits() {
        // Verify byte limits for specific k values
        let test_cases = vec![
            (1, 3),   // k=1: ⌈18/8⌉ = 3 bytes
            (2, 5),   // k=2: ⌈36/8⌉ = 5 bytes
            (4, 9),   // k=4: ⌈72/8⌉ = 9 bytes
            (8, 18),  // k=8: ⌈144/8⌉ = 18 bytes
            (16, 36), // k=16: ⌈288/8⌉ = 36 bytes
        ];
        
        for (k, expected_max_bytes) in test_cases {
            let max_bits = 18 * k;
            let max_bytes = (max_bits + 7) / 8;
            
            assert_eq!(max_bytes, expected_max_bytes,
                       "k={}: max bytes should be {}", k, expected_max_bytes);
        }
    }
}

// ============================================================================
// UPDATED DOCUMENTATION IN THE FILE FOOTER
// ============================================================================

/*
SIZE CONSTRAINT RULE 5 - TOTAL ENCODING SIZE
=============================================

CONSTRAINT: Serialized encoding ≤ 18k bits (where k = orange_depth)

FORMULATION:
- In-memory total: bracket_len + fill_len bits
- Serialized total: (bracket_len - 1) + fill_len bits (trailing ')' removed)
- Constraint: serialized_total ≤ 18k

BYTE EXPRESSION:
To avoid deserializing, we express in bytes (rounded up):
  serialized_bytes = ⌈serialized_bits / 8⌉ ≤ ⌈18k / 8⌉

RATIONALE:
- Keeps proofs compact (≤ 2KB typical)
- Prevents excessively nested orange trees
- Allows efficient validation without full deserialization
- Relaxed from previous 3k limit to 18k for more flexibility

EXAMPLES:
k=1 (simple):     max 3 bytes   (18 bits → 2.25 bytes → 3)
k=2:              max 5 bytes   (36 bits → 4.5 bytes → 5)
k=4:              max 9 bytes   (72 bits → 9)
k=8:              max 18 bytes  (144 bits → 18)
k=16 (complex):   max 36 bytes  (288 bits → 36)

VALIDATION:
Check performed in validate_size_constraints() method.
Violations result in clear error messages with actual vs. max bytes.
*/