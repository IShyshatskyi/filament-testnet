// ============================================================================
// transaction/mod.rs - Transaction Module Root
// ============================================================================

pub mod types;
pub mod flat_tx_meta;
pub mod producer_stamp;
pub mod miner_extranonce;
pub mod coinbase_mining_bytes;
pub mod txid;
mod helpers;
mod serialize;
mod validation;

// Re-export public types
pub use types::{Transaction, TxInput, TxOutput, Txid, DeserializeError,
                FlatInput, FlatOutput,
                TransactionDescriptor, WitnessEntry, ExtensionRecord, ExtensionHeader};
#[allow(deprecated)]
pub use types::TxRange;
pub use flat_tx_meta::{
    build_validity_extension, needs_validity_extension, parse_flat_tx_meta,
    parse_flat_tx_meta_scan, validate_coinbase_extensions, FlatTxMeta,
    CONSENSUS_EXT_VALIDITY_WINDOW, VALIDITY_EXTENSION_PAYLOAD_LEN,
};
pub use txid::{
    is_beacon_mempool_id, is_valid_mempool_id, mempool_chain_id, shard_chain_id, txid_from_parts,
    BEACON_CHAIN_ID, BEACON_MEMPOOL_ID, MAX_SHARD_MEMPOOL_ID, TXID_DOMAIN_TAG,
};
pub use producer_stamp::{
    build_producer_stamp_extension, is_valid_producer_id, parse_producer_stamp,
    parse_producer_stamp_for_tx, APPLICATION_EXT_PRODUCER_ID, PRODUCER_STAMP_VERSION,
};
pub use miner_extranonce::{
    build_miner_extranonce_extension, find_miner_extranonce_for_tx,
    parse_miner_extranonce_record, CONSENSUS_EXT_MINER_EXTRANONCE,
    MINER_EXTRANONCE_PAYLOAD_LEN, MINER_EXTRANONCE_VERSION,
};
pub use coinbase_mining_bytes::{
    coinb1, coinb2, coinbase_hash, coinbase_hash_from_stored_body, coinbase_mining_bytes,
    producer_stamp_marker, COINB1_LEN, EXTRANONCE_LEN, NO_PRODUCER_STAMP,
};

