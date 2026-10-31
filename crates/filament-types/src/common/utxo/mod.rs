// src/common/utxo/mod.rs
//
// UTXO-layer module: unspent output set, transaction pool, coinbase builder.
//
// ## The one durable UTXO store, plus a narrow staging overlay
//
// `PositionalUtxoDb` (rustmmrdb) is the **only** UTXO set that exists as a
// standing structure in this codebase. It is authoritative for consensus
// validation (`get_utxo`, `verify_unspent_batch`, `is_spent`) and it already
// keeps its own hot/recent-block cache (the slot store's hot window,
// `leaf_hot_window`, the mmap page cache) — there is no need, and never a
// correct reason, to duplicate "recent blocks" access outside of it.
//
// `ForkUtxoOverlay` is **not** a second UTXO set, windowed or otherwise. It
// exists to answer one narrow question: while resolving inputs across a
// sequence of blocks that are not yet durably committed anywhere — either a
// reorg's candidate fork, or the brief span between a block being applied
// in-memory and its P1DB commit landing — can block K+1 see an output block
// K just created, without touching real storage to find out? Its entries are
// created only for that purpose and purged the instant the corresponding
// P1DB commit is confirmed (see `ForkUtxoOverlay::purge_height`, called from
// every commit-confirmation point in `ShardChain`/`BeaconChain` — never from
// a chain-length/window-size trigger). In steady state, with no reorg or
// persist in flight, it should be empty. See `ForkUtxoOverlay`'s own doc
// comment for the full rationale, and CLAUDE.md's standing rule against
// reintroducing a general-purpose in-memory UTXO cache under any name.
//
// The UTXO set of a fork is not the UTXO set of the main chain — this
// overlay only ever represents the former, transiently.

pub mod beacon_subsidy;
pub mod fork_utxo_overlay;
pub mod tail_utxo_cache;
pub mod transaction_pool;
pub mod coinbase;

// Re-export the public API.
pub use fork_utxo_overlay::ForkUtxoOverlay;
pub use tail_utxo_cache::{OutputState, TailSpends, TailUtxoCache};
#[cfg(feature = "full-node")]
pub use tail_utxo_cache::LiveUtxo;
pub use transaction_pool::{fee_rate_milli, TxPool, TransactionEntry};
pub use coinbase::build_beacon_coinbase_tx;
