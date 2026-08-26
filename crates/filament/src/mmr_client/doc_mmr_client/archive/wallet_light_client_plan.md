# Wallet + MMR Light Client Integration Plan

## Executive Summary

This plan integrates the multi-shard HD wallet with the MMR light client system, enabling users to:
- Manage keys for 16 chains (1 beacon + 15 shards) from one seed
- Verify transactions without downloading full blockchain
- Track balances across all chains with cryptographic proofs
- Create and broadcast transactions with SPV security

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    User Application Layer                    │
│  (CLI wallet, GUI, Mobile app, Browser extension)           │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              LightClientWallet (NEW)                         │
│  ┌────────────────────┐  ┌────────────────────────────────┐ │
│  │  WalletManager     │  │  MultiChainClient              │ │
│  │  - Keys            │  │  - BeaconChainHandler          │ │
│  │  - Addresses       │  │  - ShardChainHandler (x15)     │ │
│  │  - UTXOs           │  │  - Proof verification          │ │
│  │  - Balances        │  │  - Sync coordination           │ │
│  └────────────────────┘  └────────────────────────────────┘ │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              Network Protocol Layer                          │
│  - Request/response for proofs                               │
│  - Transaction broadcast                                     │
│  - Peer management                                           │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. LightClientWallet (NEW)

**Purpose**: Unified interface combining wallet and light client

**Location**: `src/wallet/light_client_wallet.rs`

```rust
pub struct LightClientWallet {
    /// HD wallet for key management
    wallet_manager: WalletManager,
    
    /// Multi-chain light client for verification
    light_client: MultiChainClient,
    
    /// Transaction builder factory
    tx_builder: TransactionBuilderFactory,
    
    /// UTXO tracker with proof storage
    utxo_tracker: ProofBackedUTXOTracker,
}
```

**Key Features**:
- Single API for wallet operations with SPV security
- Automatic proof verification for all operations
- Cross-chain transaction coordination
- Persistent storage of proofs and state

### 2. ProofBackedUTXOTracker (NEW)

**Purpose**: Track UTXOs with cryptographic proofs

**Location**: `src/wallet/utxo_tracker.rs`

```rust
pub struct ProofBackedUTXOTracker {
    /// UTXOs per chain
    utxos: HashMap<u8, UTXOSet>,
    
    /// Inclusion proofs for UTXOs
    inclusion_proofs: HashMap<UTXOId, TransactionInclusionProof>,
    
    /// Block confirmations tracker
    confirmations: HashMap<UTXOId, u32>,
}

pub struct TransactionInclusionProof {
    /// Transaction merkle proof (tx -> block)
    merkle_proof: Vec<[u8; 32]>,
    
    /// Block inclusion proof (block -> chain)
    block_proof: MMRBatchProof,
    
    /// Block height
    height: u32,
    
    /// Chain ID
    chain_id: u8,
}
```

**Key Features**:
- Every UTXO has cryptographic proof of existence
- Can verify UTXO validity without full node
- Tracks confirmation depth
- Detects chain reorganizations

### 3. TransactionBuilderFactory (NEW)

**Purpose**: Create transactions with automatic proof handling

**Location**: `src/wallet/transaction_builder_factory.rs`

```rust
pub struct TransactionBuilderFactory {
    /// Wallet for signing
    wallet: Arc<RwLock<WalletManager>>,
    
    /// Light client for verification
    client: Arc<MultiChainClient>,
}
```

**Key Features**:
- Verifies input UTXOs before spending
- Generates change addresses
- Calculates fees based on network data
- Broadcasts with confirmation tracking

## Integration Points

### A. Wallet → Light Client

**Data Flow**: Wallet needs blockchain data

1. **Balance Queries**
   ```rust
   // Wallet requests balance for address
   let addresses = wallet.get_all_addresses(0, 0);
   
   // Light client fetches UTXOs with proofs
   for (chain_id, address) in addresses {
       let utxos = client.get_utxos_for_address(chain_id, &address).await?;
       
       // Each UTXO comes with inclusion proof
       for (utxo, proof) in utxos {
           // Verify proof before trusting UTXO
           if client.verify_transaction_inclusion(chain_id, &utxo, &proof)? {
               wallet.add_utxo(utxo)?;
           }
       }
   }
   ```

2. **Transaction Status**
   ```rust
   // Check if transaction confirmed
   let tx_hash = [0x42; 32];
   let status = client.get_transaction_status(chain_id, tx_hash).await?;
   
   match status {
       TxStatus::Confirmed { height, proof } => {
           // Verify proof
           client.verify_batch_proof(&proof)?;
           wallet.confirm_transaction(tx_hash, height)?;
       }
       TxStatus::Pending => { /* wait */ }
       TxStatus::NotFound => { /* rebroadcast? */ }
   }
   ```

3. **Chain Reorganization Detection**
   ```rust
   // Light client detects reorg
   client.subscribe_to_reorgs(|reorg_event| {
       // Revert affected transactions
       wallet.handle_reorg(
           reorg_event.chain_id,
           reorg_event.fork_height,
           reorg_event.old_blocks,
           reorg_event.new_blocks,
       )?;
   });
   ```

### B. Light Client → Wallet

**Data Flow**: Light client needs key material

1. **Address Generation**
   ```rust
   // Light client needs address to monitor
   let address = wallet.new_address(chain_id)?;
   
   // Subscribe to transactions for this address
   client.watch_address(chain_id, address).await?;
   ```

2. **Transaction Signing**
   ```rust
   // Build unsigned transaction
   let unsigned_tx = TransactionBuilder::new(chain_id, config)?
       .add_output(recipient, amount)?
       .build_from_wallet(&mut wallet)?;
   
   // Sign with wallet keys
   let signed_tx = wallet.sign_transaction(unsigned_tx)?;
   
   // Broadcast via light client
   client.broadcast_transaction(chain_id, signed_tx).await?;
   ```

3. **Proof Verification**
   ```rust
   // Light client verifies using wallet's addresses
   let my_addresses = wallet.get_all_addresses(0, 0);
   
   for tx in block.transactions {
       for output in tx.outputs {
           if my_addresses.values().any(|a| a.matches(&output)) {
               // This output belongs to us
               let utxo = UTXO::from_output(tx.hash(), output);
               wallet.add_utxo(utxo)?;
           }
       }
   }
   ```

## API Design

### High-Level Wallet Operations

```rust
impl LightClientWallet {
    /// Create new wallet with light client
    pub async fn new(
        mnemonic: &str,
        password: &str,
        storage: Box<dyn LightClientStorage>,
    ) -> Result<Self, String>;
    
    /// Get verified balance for chain
    pub async fn get_balance(&self, chain_id: u8) -> Result<u64, String>;
    
    /// Get verified portfolio summary
    pub async fn get_portfolio(&self) -> Result<PortfolioSummary, String>;
    
    /// Send transaction with SPV security
    pub async fn send(
        &mut self,
        chain_id: u8,
        to_address: ShardAddress,
        amount: u64,
    ) -> Result<Txid, String>;
    
    /// Send to multiple recipients
    pub async fn send_many(
        &mut self,
        chain_id: u8,
        outputs: Vec<(ShardAddress, u64)>,
    ) -> Result<Txid, String>;
    
    /// Get transaction history with proofs
    pub async fn get_history(
        &self,
        chain_id: u8,
    ) -> Result<Vec<VerifiedTransaction>, String>;
    
    /// Sync all chains
    pub async fn sync(&mut self) -> Result<SyncResult, String>;
    
    /// Check transaction confirmations
    pub async fn get_confirmations(
        &self,
        chain_id: u8,
        tx_hash: Txid,
    ) -> Result<u32, String>;
}
```

### Lower-Level Operations

```rust
impl LightClientWallet {
    /// Get UTXOs with inclusion proofs
    pub async fn get_utxos_with_proofs(
        &self,
        chain_id: u8,
    ) -> Result<Vec<(UTXO, TransactionInclusionProof)>, String>;
    
    /// Verify UTXO is still valid
    pub async fn verify_utxo(
        &self,
        chain_id: u8,
        utxo: &UTXO,
    ) -> Result<bool, String>;
    
    /// Get light client sync status
    pub fn get_sync_status(&self) -> HashMap<u8, ChainSyncStatus>;
    
    /// Export proof for external verification
    pub async fn export_balance_proof(
        &self,
        chain_id: u8,
    ) -> Result<BalanceProof, String>;
}
```

## Data Structures

### VerifiedTransaction

```rust
pub struct VerifiedTransaction {
    /// Transaction data
    pub tx: Transaction,
    
    /// Chain ID
    pub chain_id: u8,
    
    /// Block height (if confirmed)
    pub height: Option<u32>,
    
    /// Confirmations
    pub confirmations: u32,
    
    /// Inclusion proof (if confirmed)
    pub proof: Option<TransactionInclusionProof>,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// Amount (for display)
    pub amount: i64, // Negative for sends, positive for receives
}
```

### BalanceProof

```rust
pub struct BalanceProof {
    /// Chain ID
    pub chain_id: u8,
    
    /// Total balance
    pub balance: u64,
    
    /// UTXOs proving this balance
    pub utxos: Vec<UTXO>,
    
    /// Inclusion proofs for each UTXO
    pub inclusion_proofs: Vec<TransactionInclusionProof>,
    
    /// Chain summary showing current state
    pub chain_summary: MMRChainSummary,
}
```

### SyncResult

```rust
pub struct SyncResult {
    /// Chains synced
    pub chains_synced: Vec<u8>,
    
    /// New blocks per chain
    pub new_blocks: HashMap<u8, u32>,
    
    /// New transactions detected
    pub new_transactions: Vec<VerifiedTransaction>,
    
    /// Balance changes
    pub balance_changes: HashMap<u8, i64>,
    
    /// Time taken
    pub duration_ms: u64,
}
```

## Implementation Phases

### Phase 1: Basic Integration (Week 1)

**Goal**: Wallet can query light client for data

**Deliverables**:
1. `LightClientWallet` struct with basic initialization
2. Balance queries with proof verification
3. Address monitoring setup
4. Basic UTXO tracking

**Files to Create**:
- `src/wallet/light_client_wallet.rs`
- `src/wallet/utxo_tracker.rs`

**Files to Modify**:
- `src/wallet/wallet_manager.rs` - Add light client field
- `src/wallet/mod.rs` - Export new types

### Phase 2: Transaction Building (Week 2)

**Goal**: Wallet can create and broadcast transactions

**Deliverables**:
1. `TransactionBuilderFactory` for SPV-aware transactions
2. Input verification before spending
3. Transaction broadcasting via light client
4. Confirmation tracking

**Files to Create**:
- `src/wallet/transaction_builder_factory.rs`

**Files to Modify**:
- `src/wallet/transaction_builder.rs` - Add verification hooks
- `src/mmr_client/protocol.rs` - Add transaction broadcast

### Phase 3: Proof Storage (Week 3)

**Goal**: Persistent proofs for offline verification

**Deliverables**:
1. `ProofBackedUTXOTracker` with storage
2. Proof caching and indexing
3. Proof export/import
4. Proof verification API

**Files to Create**:
- `src/wallet/proof_storage.rs`

**Files to Modify**:
- `src/mmr_client/storage.rs` - Add proof storage
- `src/wallet/utxo_tracker.rs` - Integrate storage

### Phase 4: Multi-Chain Coordination (Week 4)

**Goal**: Seamless operation across all chains

**Deliverables**:
1. Unified balance queries across chains
2. Cross-chain transaction detection
3. Parallel sync for all chains
4. Portfolio management

**Files to Create**:
- `src/wallet/portfolio_manager.rs`

**Files to Modify**:
- `src/mmr_client/multi_chain_client.rs` - Add batch operations
- `src/wallet/balance.rs` - Add multi-chain helpers

### Phase 5: Advanced Features (Week 5-6)

**Goal**: Production-ready features

**Deliverables**:
1. Chain reorganization handling
2. Transaction history with proofs
3. Export balance proofs for auditing
4. SPV fraud proofs
5. Wallet recovery from seed

**Files to Create**:
- `src/wallet/reorg_handler.rs`
- `src/wallet/history_tracker.rs`
- `src/wallet/fraud_proofs.rs`

## Network Protocol Extensions

### New Request Types

```rust
pub enum LightClientRequest {
    // Existing...
    GetChainSummary { recent_count: usize },
    GetRangeProof { start_height: u32, end_height: u32 },
    
    // NEW: Wallet-specific requests
    GetUTXOsForAddress {
        chain_id: u8,
        address: ShardAddress,
        start_height: u32,
    },
    
    GetTransactionWithProof {
        chain_id: u8,
        tx_hash: [u8; 32],
    },
    
    BroadcastTransaction {
        chain_id: u8,
        tx: Transaction,
    },
    
    GetTransactionStatus {
        chain_id: u8,
        tx_hash: [u8; 32],
    },
    
    WatchAddress {
        chain_id: u8,
        address: ShardAddress,
    },
}
```

### New Response Types

```rust
pub enum LightClientResponse {
    // Existing...
    ChainSummary(MMRChainSummary),
    RangeProof { proof: MMRRangeProof, blocks: Vec<CompactBlockHeader> },
    
    // NEW: Wallet-specific responses
    UTXOs {
        utxos: Vec<UTXO>,
        inclusion_proofs: Vec<TransactionInclusionProof>,
    },
    
    TransactionWithProof {
        tx: Transaction,
        merkle_proof: Vec<[u8; 32]>,
        block_proof: MMRBatchProof,
        height: u32,
    },
    
    TransactionBroadcasted {
        tx_hash: [u8; 32],
        accepted: bool,
    },
    
    TransactionStatus {
        status: TxStatus,
        confirmations: u32,
        proof: Option<TransactionInclusionProof>,
    },
    
    AddressWatched {
        address: ShardAddress,
        from_height: u32,
    },
}
```

## Security Considerations

### 1. Proof Verification

**All operations must verify cryptographic proofs**:

```rust
async fn get_balance_secure(&self, chain_id: u8) -> Result<u64, String> {
    // Get UTXOs from network
    let response = self.client.request_utxos(chain_id, &self.addresses).await?;
    
    let mut verified_balance = 0u64;
    
    for (utxo, proof) in response.utxos {
        // CRITICAL: Verify proof before trusting UTXO
        if !self.verify_inclusion_proof(chain_id, &utxo, &proof)? {
            warn!("Rejected UTXO with invalid proof: {:?}", utxo);
            continue;
        }
        
        verified_balance += utxo.value;
    }
    
    Ok(verified_balance)
}
```

### 2. Chain Reorganization Protection

**Detect and handle reorgs**:

```rust
async fn handle_reorg(&mut self, event: ReorgEvent) -> Result<(), String> {
    // Revert transactions in orphaned blocks
    for block_height in event.fork_height..event.old_tip {
        let txs = self.history.get_txs_at_height(block_height);
        
        for tx in txs {
            // Move UTXOs back to unconfirmed
            self.utxo_tracker.unconfirm_transaction(tx.hash())?;
        }
    }
    
    // Re-verify transactions in new chain
    for block in event.new_blocks {
        self.scan_block_for_transactions(block).await?;
    }
    
    Ok(())
}
```

### 3. Peer Trust Model

**Don't trust any single peer**:

```rust
async fn verify_with_multiple_peers(
    &self,
    request: LightClientRequest,
) -> Result<LightClientResponse, String> {
    let peers = self.client.get_best_peers(3)?;
    let mut responses = Vec::new();
    
    for peer in peers {
        let response = self.client.request_from_peer(peer, request.clone()).await?;
        responses.push(response);
    }
    
    // Verify responses match
    if responses.iter().all(|r| r == &responses[0]) {
        Ok(responses[0].clone())
    } else {
        Err("Peers gave conflicting responses".to_string())
    }
}
```

### 4. Key Security

**Never expose private keys**:

```rust
impl LightClientWallet {
    /// Sign transaction WITHOUT exposing keys
    pub fn sign_transaction(&self, tx: &mut Transaction) -> Result<(), String> {
        // Keys stay inside wallet, never exported
        let keys = self.derive_signing_keys_internal(tx)?;
        TransactionSigner::sign(tx, &keys, tx.chain_id)?;
        
        // Keys dropped here (not returned)
        Ok(())
    }
    
    /// Export only public data
    pub fn export_public_data(&self) -> WalletPublicData {
        WalletPublicData {
            addresses: self.wallet_manager.get_all_addresses(0, 0),
            balances: self.wallet_manager.all_balances(),
            // NO PRIVATE KEYS
        }
    }
}
```

## Testing Strategy

### Unit Tests

1. **Proof Verification**
   ```rust
   #[test]
   fn test_reject_invalid_proof() {
       let wallet = create_test_wallet();
       let bad_proof = create_invalid_proof();
       
       assert!(wallet.verify_inclusion_proof(&bad_proof).is_err());
   }
   ```

2. **Balance Calculation**
   ```rust
   #[test]
   fn test_balance_from_utxos() {
       let wallet = create_test_wallet();
       
       // Add UTXOs with proofs
       wallet.add_verified_utxo(utxo1, proof1);
       wallet.add_verified_utxo(utxo2, proof2);
       
       assert_eq!(wallet.get_balance(1)?, 300_00000000);
   }
   ```

3. **Reorg Handling**
   ```rust
   #[test]
   fn test_reorg_reverts_transactions() {
       let mut wallet = create_test_wallet();
       
       // Confirm transaction
       wallet.confirm_tx(tx_hash, 100);
       
       // Trigger reorg
       wallet.handle_reorg(fork_at_90);
       
       // Transaction should be unconfirmed
       assert_eq!(wallet.get_confirmations(tx_hash)?, 0);
   }
   ```

### Integration Tests

1. **End-to-End Transaction**
   ```rust
   #[tokio::test]
   async fn test_send_and_verify() {
       let mut wallet = LightClientWallet::new_test().await;
       
       // Send transaction
       let tx_hash = wallet.send(1, recipient, 100_00000000).await?;
       
       // Wait for confirmation
       wallet.wait_for_confirmations(1, tx_hash, 1).await?;
       
       // Verify with proof
       let proof = wallet.get_transaction_proof(1, tx_hash).await?;
       assert!(wallet.verify_transaction_proof(&proof)?);
   }
   ```

2. **Multi-Chain Sync**
   ```rust
   #[tokio::test]
   async fn test_sync_all_chains() {
       let mut wallet = LightClientWallet::new_test().await;
       
       // Sync all chains
       let result = wallet.sync().await?;
       
       assert_eq!(result.chains_synced.len(), 16); // 1 beacon + 15 shards
   }
   ```

## Performance Optimization

### 1. Parallel Sync

```rust
async fn sync_all_chains(&mut self) -> Result<SyncResult, String> {
    let mut handles = Vec::new();
    
    // Sync chains in parallel
    for chain_id in 0..=15 {
        let client = self.light_client.clone();
        handles.push(tokio::spawn(async move {
            client.sync_chain(chain_id).await
        }));
    }
    
    // Wait for all
    let results = futures::future::join_all(handles).await;
    
    // Aggregate results
    aggregate_sync_results(results)
}
```

### 2. Proof Caching

```rust
struct ProofCache {
    cache: Arc<RwLock<HashMap<[u8; 32], CachedProof>>>,
    max_size: usize,
}

impl ProofCache {
    async fn get_or_fetch(&self, tx_hash: [u8; 32]) -> Result<Proof, String> {
        // Check cache first
        if let Some(cached) = self.cache.read().await.get(&tx_hash) {
            if !cached.is_stale() {
                return Ok(cached.proof.clone());
            }
        }
        
        // Fetch from network
        let proof = self.fetch_from_network(tx_hash).await?;
        
        // Cache it
        self.cache.write().await.insert(tx_hash, CachedProof {
            proof: proof.clone(),
            cached_at: now(),
        });
        
        Ok(proof)
    }
}
```

### 3. Incremental Updates

```rust
async fn incremental_sync(&mut self, chain_id: u8) -> Result<(), String> {
    let last_height = self.get_last_synced_height(chain_id)?;
    let current_height = self.client.get_chain_height(chain_id).await?;
    
    if current_height > last_height {
        // Only sync new blocks
        let range_proof = self.client
            .get_range_proof(chain_id, last_height + 1, current_height)
            .await?;
        
        self.apply_range_proof(chain_id, range_proof)?;
    }
    
    Ok(())
}
```

## User Experience

### CLI Wallet Example

```bash
# Create wallet
$ jax-wallet create --words 12

# Show addresses
$ jax-wallet addresses
Beacon (JXN): jxn1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
Shard 1 (JAX): jax1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
Shard 2 (JAX): jax2qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
...

# Sync (fetches proofs from network)
$ jax-wallet sync
✓ Synced beacon chain (height: 50000)
✓ Synced shard 1 (height: 48500)
✓ Synced shard 2 (height: 49100)
...

# Check balance (all verified with proofs)
$ jax-wallet balance
JXN (Beacon):  5000.00000000 (verified with 3 UTXOs)
JAX (Shard 1): 2500.00000000 (verified with 2 UTXOs)
JAX (Shard 2): 1200.00000000 (verified with 1 UTXO)
Total: 8700.00000000

# Send (builds, signs, broadcasts)
$ jax-wallet send --chain 1 --to jax1q... --amount 100
Building transaction...
Selected 2 inputs (150.0 JAX)
Change: 49.9999 JAX
Fee: 0.0001 JAX
Sign transaction? [y/N] y
Broadcasting...
✓ Transaction sent: 0x1234...
Waiting for confirmation...
✓ Confirmed in block 48,501 (1 confirmation)

# Verify transaction
$ jax-wallet verify 0x1234...
✓ Transaction found in block 48,501
✓ Block included in chain (MMR proof verified)
✓ 12 confirmations
Status: CONFIRMED
```

## Success Metrics

1. **Security**: 100% of operations verify cryptographic proofs
2. **Performance**: Sync 16 chains in < 10 seconds
3. **Storage**: Proof storage < 1MB per 1000 transactions
4. **Reliability**: Handle chain reorgs automatically
5. **UX**: Single-command operations (sync, send, balance)

## Next Steps

1. **Review this plan** with team
2. **Set up dev environment** for integration
3. **Start Phase 1** implementation
4. **Create integration tests** for each phase
5. **Document APIs** as they're built
6. **Plan deployment** for testnet

## Questions to Resolve

1. Should we support multiple wallets per client?
2. What's the target sync time for initial setup?
3. How many peers should we query for verification?
4. Should proofs be stored indefinitely or pruned?
5. What's the minimum confirmation count for "verified"?
6. How do we handle wallet recovery after data loss?

---

**Status**: 📋 Planning Complete - Ready for Review
**Timeline**: 6 weeks for full implementation
**Risk Level**: Medium (depends on network protocol stability)
