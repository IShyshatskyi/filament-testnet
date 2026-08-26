// filament-types/src/tx_sighash.rs — per-input signature preimage.
//
// Domain-separated by `chain_id` (the sole cross-shard replay protection
// under the single-key address model) and binds the full flat input/output
// set plus the specific input being signed.

use crate::transaction::{FlatInput, FlatOutput};

/// Compute the BLAKE3 sighash for `inputs[input_index]`.
pub fn flat_tx_sighash(
    chain_id: u8,
    tx_version: u8,
    locktime: u32,
    expiration_height: u32,
    inputs: &[FlatInput],
    outputs: &[FlatOutput],
    input_index: u32,
) -> Result<[u8; 32], String> {
    if input_index as usize >= inputs.len() {
        return Err(format!("sighash input_index {input_index} out of range"));
    }

    let mut preimage = Vec::new();
    preimage.push(chain_id);
    preimage.push(tx_version);
    preimage.extend_from_slice(&locktime.to_le_bytes());
    preimage.extend_from_slice(&expiration_height.to_le_bytes());

    preimage.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
    for input in inputs {
        preimage.extend_from_slice(&input.prev_height.to_le_bytes());
        preimage.extend_from_slice(&input.prev_output_idx.to_le_bytes());
    }

    preimage.extend_from_slice(&(outputs.len() as u32).to_le_bytes());
    for output in outputs {
        preimage.extend_from_slice(&output.value.to_le_bytes());
        preimage.extend_from_slice(&output.recipient);
    }

    preimage.extend_from_slice(&input_index.to_le_bytes());

    Ok(*blake3::hash(&preimage).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_range_input_index_errors() {
        let r = flat_tx_sighash(1, 1, 0, 0, &[], &[], 0);
        assert!(r.is_err());
    }

    #[test]
    fn different_chain_id_gives_different_sighash() {
        let inputs = [FlatInput { prev_height: 1, prev_output_idx: 0 }];
        let outputs = [FlatOutput { value: 100, recipient: [1u8; 32] }];
        let a = flat_tx_sighash(1, 1, 0, 0, &inputs, &outputs, 0).unwrap();
        let b = flat_tx_sighash(2, 1, 0, 0, &inputs, &outputs, 0).unwrap();
        assert_ne!(a, b);
    }
}
