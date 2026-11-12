# Security model

What Filament guarantees, what it assumes, and what it does not do. To report a problem see
[SECURITY.md](../SECURITY.md).

## The threat it is built against

A light client that asks **one** full node for the chain can be lied to in two ways. The node can
forge data: that fails here, because every header's proof of work and linkage is checked and the
chain weight is computed from the leaves. Or the node can **withhold** a heavier competing chain, so
the client follows a weaker but valid one (selective disclosure, an eclipse). A proof cannot detect
that, because the missing chain is exactly what was not sent. Only a second independent source can.

Hence the rule: **Filament trusts a state only when at least two Keystones hold it** (a quorum of
`required_keystones()`). One honest Keystone among those queried is enough to expose a liar, and the
heaviest verified state wins.

## What is verified, and against what

| Property | Verified against |
|---|---|
| Block 0 | A genesis generated locally from a preset or the genesis file. Not from a peer. |
| Every header's proof of work | The target derived from the header's rBits and the network's genesis facts. |
| Linkage | The root Filament computed itself. |
| Chain weight | The leaves' rBits, summed by the MMR. Never a peer's number. |
| A shard block's work and place | The shard block check: aux-header PoW, hash-sorting route, merged-mining sibling path, chain-count range. |
| A payment | An output inclusion proof against the block's `tx_merkle_root`, in a block of a chain Filament verified. |

Two implementations of these functions exist (the node's, and the clean-room one here); they are held
byte-for-byte equal by a shared test file ([vectors.md](vectors.md)).

## No zero-knowledge proofs

Every proof is a hash-based inclusion or weight proof, and no zero-knowledge scheme will be added. This is
a position of mathematics, not an omission and not fashion:

* A ZK "proof" is a probabilistic argument, not an absolute proof, and its security proofs are incomplete in a
  trustless setting.
* Its assumptions are old assumptions pushed beyond their valid domain (pairing-based constructions used where they
  were never proven), and a trusted setup violates "trustless" by definition: you trust the ceremony.
* In a trustless setting only mathematics is trusted: not cryptography PhDs, not ceremonies, not assumptions without
  proof, not constructions without decades of cryptanalysis.
* Fork choice must be checkable from independent peers; it must not collapse onto one data provider.

Filament uses long-studied hash and Merkle structure with proof of work instead. The full argument is in the
repository README. No outside authority or consultancy is needed to hold this position.

## Trust assumptions

* The genesis config is correct. It is derived locally, so a wrong preset is a build-time defect that
  the vectors catch, not a runtime trust decision.
* At least one of the Keystones you query is honest. With a quorum of two, one liar is outvoted.
* The network's proof of work and hash functions hold.
* The machine running Filament and its data directory are yours.

## What Filament does not do

* It does **not** validate transactions: signatures, unspent inputs, fees. It relies on the chain's proof
  of work for that, like every light client.
* It does not enforce consensus rules, mine, or hold a UTXO set.
* It does not check that a header's claimed work equals what the difficulty adjustment would produce.
  A fake chain with cheap work is rejected by comparing Keystones, not by the single-chain check.
* It does not verify shards opened after genesis ([thin-sync.md](thin-sync.md), Limits).

## Operating it safely

* Query **at least two** Keystones run by different operators (`--keystone`, `--keystone-extra`).
  `--allow-single-keystone` is for local development only.
* The local API listens on loopback. Do not expose `127.0.0.1:7380` or a Keystone's wallet port to the
  internet; the wallet routes are experimental.
* Pass the genesis file of a custom chain (`--genesis-file`). A wrong network shows up as
  `Invalid chain summary proof` or `genesis mismatch` at the P2P handshake, never as silent trust.
* The optional hot key (`hot_key.json`) is encrypted under a password. Keep the data directory private.
* This is unaudited testnet software ([DISCLAIMER.md](../DISCLAIMER.md)). Do not hold funds that matter.

## Reporting

[SECURITY.md](../SECURITY.md): email, scope, and the disclosure window.
