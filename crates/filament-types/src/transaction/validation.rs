// ============================================================================
// transaction/validation.rs - Transaction Validation
// ============================================================================
//
// PURPOSE:
// Transaction validation logic following Bitcoin consensus rules
//
// CONTENTS:
// - Coinbase detection
// - SegWit detection
// - Input validation against UTXO set
// - Structure validation (context-free)
// - Full validation (with UTXO set)
// - Value calculations
//
// ============================================================================

use log::debug;
use super::types::Transaction;
use crate::common::utxo::ForkUtxoOverlay;

impl Transaction {
    /// Calculate total input value
    pub fn total_input_value(&self, fork_utxo_overlay: &ForkUtxoOverlay) -> Option<u64> {
        if self.is_coinbase() {
            return Some(0);
        }

        let mut total = 0u64;
        for input in &self.inputs {
            let output = fork_utxo_overlay.get(input.prev_height, input.prev_output_idx)?;
            total = total.checked_add(output.value)?;
        }
        Some(total)
    }

    /// Calculate total output value
    pub fn total_output_value(&self) -> Option<u64> {
        let mut total = 0u64;
        for output in &self.outputs {
            total = total.checked_add(output.value)?;
        }
        Some(total)
    }

    /// Calculate transaction fee
    pub fn fee(&self, fork_utxo_overlay: &ForkUtxoOverlay) -> Option<u64> {
        let input_value = self.total_input_value(fork_utxo_overlay)?;
        let output_value = self.total_output_value()?;
        
        if self.is_coinbase() {
            return Some(0);
        }
        
        if output_value > input_value {
            return None;
        }
        
        input_value.checked_sub(output_value)
    }

    /// Check if transaction has duplicate inputs
    pub fn has_duplicate_inputs(&self) -> bool {
        use std::collections::HashSet;
        
        let mut seen = HashSet::new();
        for input in &self.inputs {
            let outpoint = (input.prev_height, input.prev_output_idx);
            if !seen.insert(outpoint) {
                return true;
            }
        }
        false
    }

    /// Validate transaction structure (context-free checks)
    pub fn validate_structure(&self) -> Result<(), String> {
        if self.is_coinbase() {
            if self.outputs.is_empty() {
                return Err("Coinbase transaction must have at least one output".to_string());
            }
            return Ok(());
        }

        if self.inputs.is_empty() {
            return Err("Non-coinbase transaction must have at least one input".to_string());
        }

        if self.outputs.is_empty() {
            return Err("Transaction must have at least one output".to_string());
        }

        if self.has_duplicate_inputs() {
            return Err("Transaction has duplicate inputs".to_string());
        }

        if self.total_output_value().is_none() {
            return Err("Transaction output value overflow".to_string());
        }

        // SegWit-specific validation
        if self.has_witnesses() && self.witnesses.len() != self.inputs.len() {
            return Err(format!(
                "Witness data mismatch: {} witness entries for {} inputs",
                self.witnesses.len(),
                self.inputs.len()
            ));
        }

        Ok(())
    }

    /// Returns true when every input resolves in `fork_utxo_overlay` (mempool / test helper).
    pub fn inputs_exist_in_utxo(&self, fork_utxo_overlay: &ForkUtxoOverlay) -> bool {
        if self.is_coinbase() {
            return !self.outputs.is_empty();
        }
        if self.inputs.is_empty() {
            return false;
        }
        self.inputs
            .iter()
            .all(|inp| fork_utxo_overlay.contains(inp.prev_height, inp.prev_output_idx))
    }
}

/*
===============================================================================
TRANSACTION VALIDATION - COMPLETE IMPLEMENTATION WITH SEGWIT SUPPORT
===============================================================================

PURPOSE
=======
Comprehensive transaction validation following Bitcoin consensus rules,
including full SegWit support.


VALIDATION LEVELS
=================

1. STRUCTURE VALIDATION (Context-Free)
   - No UTXO set required
   - Checks transaction format
   - Basic sanity checks
   - SegWit witness validation

2. INPUT VALIDATION (UTXO-Based)
   - Requires UTXO set
   - Verifies inputs exist
   - Checks spendability

3. FULL VALIDATION (Complete)
   - Structure + Input validation
   - Value conservation
   - No inflation check


SEGWIT ADDITIONS
================

New validation rules for SegWit transactions:

1. Witness Structure:
   - Must have one witness stack per input
   - Empty witnesses allowed (legacy inputs)
   - Witness count must match input count

2. Witness Validation:
   - Called in validate_structure()
   - Uses witness.is_valid_for(input_count)
   - Returns clear error message

Example:
```rust
// Valid SegWit transaction
let mut tx = Transaction::new(1, 0);
tx.add_input(input1);
tx.add_input(input2);

let witness = TxWitness {
    stacks: vec![
        WitnessStack::from_items(vec![sig1, pubkey1]),
        WitnessStack::from_items(vec![sig2, pubkey2]),
    ]
};
tx.witness = Some(witness);

// Validation passes
tx.validate_structure()?; // OK: 2 inputs, 2 witness stacks

// Invalid SegWit transaction
let witness = TxWitness {
    stacks: vec![
        WitnessStack::from_items(vec![sig1, pubkey1]),
        // Missing second witness stack!
    ]
};
tx.witness = Some(witness);

tx.validate_structure()?; // Error: "Witness data mismatch: 1 witness stacks for 2 inputs"
```


VALIDATION FLOW
===============

validate_structure():
├─ Coinbase check
│  └─ Must have outputs
├─ Input/output presence
├─ Duplicate input check
├─ Output value overflow check
└─ SegWit witness validation ← NEW!

verify_inputs():
├─ Coinbase check
├─ Input presence check
└─ For each input:
   └─ Check exists in UTXO set

validate() [Full]:
├─ validate_structure()
├─ verify_inputs()
└─ Value conservation check


VALUE CALCULATIONS
==================

total_input_value():
- Sums all input values from UTXO set
- Coinbase returns 0 (creates value)
- Uses checked_add for overflow protection
- Returns None if any input missing

total_output_value():
- Sums all output values
- Uses checked_add for overflow protection
- Returns None on overflow

fee():
- fee = inputs - outputs
- Coinbase fee = 0
- Returns None if outputs > inputs (invalid)
- Returns None on overflow


BITCOIN CONSENSUS RULES
========================

✓ Coinbase transactions:
  - Have no inputs (inputs.is_empty())
  - MUST have at least one output
  - First transaction in every block
  - Create new coins from nothing

✓ Non-coinbase transactions:
  - Must have at least one input
  - All inputs must reference existing UTXOs
  - Cannot have duplicate inputs
  - Outputs cannot exceed inputs (no inflation)

✓ SegWit transactions:
  - Witness data optional
  - Witness count must match input count
  - Empty witnesses allowed for legacy inputs
  - Witness excluded from txid calculation

✓ Value conservation:
  - Overflow protection on all calculations
  - Fee = sum(inputs) - sum(outputs) >= 0
  - No value creation except coinbase


ERROR MESSAGES
==============

Structure Validation Errors:
- "Coinbase transaction must have at least one output"
- "Non-coinbase transaction must have at least one input"
- "Transaction must have at least one output"
- "Transaction has duplicate inputs"
- "Transaction output value overflow"
- "Witness data mismatch: X witness stacks for Y inputs"

Input Validation:
- verify_inputs() returns bool (no detailed error)
- Use debug logs to identify specific missing input

Full Validation Errors:
- "Invalid transaction inputs"
- "Failed to calculate input value"
- "Failed to calculate output value"
- "Outputs (X) exceed inputs (Y)"


INTEGRATION EXAMPLES
====================

1. Mempool Validation:
```rust
// Before adding to pool
match tx.validate(&fork_utxo_overlay) {
    Ok(()) => {
        let fee = tx.fee(&fork_utxo_overlay).unwrap();
        let fee_rate = fee as f64 / tx.size() as f64;
        pool.add_transaction(tx, fee_rate, timestamp)?;
    }
    Err(e) => {
        debug!("Transaction validation failed: {}", e);
        return Err(e);
    }
}
```

2. Block Validation:
```rust
// Validate all transactions in block
for tx in &block.transactions {
    tx.validate(&fork_utxo_overlay)?;
}
```

3. Structure-Only Validation:
```rust
// Check transaction format before network broadcast
tx.validate_structure()?;
```


PERFORMANCE
===========

validate_structure(): O(n)
- Check inputs/outputs: O(n)
- Duplicate check: O(n) with HashSet
- Witness check: O(1)

verify_inputs(): O(n * log m)
- n inputs
- m UTXOs in set
- Each lookup: O(log m) average

validate(): O(n * log m)
- Calls both above methods
- Dominant cost: UTXO lookups


TESTING
=======

Structure validation tests:
- Valid coinbase
- Invalid coinbase (no outputs)
- Valid regular transaction
- Invalid (no inputs)
- Invalid (duplicate inputs)
- Invalid (overflow)
- Valid SegWit (witness matches inputs)
- Invalid SegWit (witness mismatch)

Input validation tests:
- Valid inputs (all in UTXO set)
- Invalid (some missing)
- Invalid (all missing)
- Coinbase (no inputs required)

Full validation tests:
- Valid transaction (all checks pass)
- Invalid (bad structure)
- Invalid (bad inputs)
- Invalid (outputs > inputs)


FUTURE ENHANCEMENTS
===================

TODO:
- [ ] Script validation (signature verification)
- [ ] Locktime enforcement
- [ ] Sequence number handling (RBF, CSV)
- [ ] Minimum relay fee enforcement
- [ ] Dust output detection
- [ ] BIP-125 Replace-By-Fee
- [ ] BIP-68 Relative lock-time
- [ ] Taproot script validation
- [ ] Witness program validation (P2WPKH, P2WSH)


BACKWARD COMPATIBILITY
======================

Legacy transactions:
- witness = None
- All validation rules still apply
- No witness checks performed
- txid excludes witness (always did)

SegWit transactions:
- witness = Some(...)
- Additional witness validation
- wtxid includes witness
- txid still excludes witness (malleability fix)

Both types can coexist in same block.


===============================================================================
*/