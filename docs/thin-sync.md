# Thin sync

Thin sync is how Filament follows a chain with the least traffic and the least trust. It replaces
polling a full chain summary (the last 100 blocks plus a batch proof, 134–159 KB per poll per
Keystone) with a tiny tip poll, a once-per-session summary and incremental headers. It is enabled
with `--thin-sync` and is **off by default** until it has run against a live fleet.

## What Filament keeps

For each followed chain: the MMR **peaks**, the leaf count, the tip header and the last **16**
headers (shards: the last 16 block records). The chain weight is **computed** from the leaves, never
received. Nothing grows with the length of the chain.

## One round

Every sync tick, for each configured Keystone, concurrently:

1. **Tip poll.** `GET /chain/tip` returns the height, the leaf count and the MMR root (about 110 B).
   Equal to what Filament holds: nothing more happens.
2. **Plan.** From the answer Filament picks one of: nothing; the peer is behind; fetch headers
   `GET /chain/headers/{from}?max=N` (up to 64 consecutive headers); or a session.
3. **Session.** `GET /chain/session?headers=16`, once per connection or after any failure, a gap
   above 256 blocks, or a reorg deeper than the 16 headers held: the newest 16 headers and one range
   proof over their leaves.
4. **Check.** Each header is verified before it is applied (below). A header batch that fails any check
   falls back to a session. A session that fails verification marks that Keystone `rejected`.
5. **Quorum.** Each Keystone that answered has its own verified state. A state is trusted only when at
   least `required_keystones()` distinct Keystones **contain** it. The heaviest supported state wins.

### The header checks

* the next height;
* proof of work, against the target derived from the header's own rBits and the network's genesis facts;
* `prev_mmr_root` equals the root Filament computed itself;
* appending the leaf to the held peaks yields the `current_mmr_root` the header claims;
* for a session: the range proof verifies against the genesis anchor, its root and leaf count equal the
  response's, every header's leaf equals the proof's leaf, and only then are the peaks taken.

The genesis facts (Bitcoin anchor, initial target, frozen hash-sorting width) come from the same
trusted source as block 0: a preset, or the genesis file passed with `--genesis-file`. They are never
read from a Keystone.

### Quorum

"Contain" means: the Keystone has the same root at the same leaf count, or it is ahead and holds the
header after that tip whose `prev_mmr_root` equals that root. This tolerates lag and reorgs up to the
16 headers held. Two Keystones that disagree beyond that tolerance are reported
(`report_beacon_disagreement`) and neither state is trusted until they converge.

With one configured Keystone the quorum cannot be met; pass `--allow-single-keystone` to accept a
quorum of one (weaker trust).

## Shards

Shards use the same loop over `/shard/{id}/chain/{tip,session,headers/{from}}` for the shards in
`--thin-shard N` and for the shard of every open invoice.

Two things differ from the beacon:

* **The work.** A shard block has no proof of work of its own; its work is the PoW of the auxiliary
  beacon header it was merge-mined with, tied to the shard by a merged-mining sibling path. The
  136-byte light header is not enough, so every block arrives as a full record (about 0.3–2.2 KB)
  and passes the shard block check: target, hash-sorting route to *this* shard, sibling path to the
  header's `merged_mining_root`, and the chain count in that root inside the admissible range.
* **The anchor.** A shard's MMR starts from the beacon root at the shard's activation block, and its
  height-0 block must carry the difficulty derived from that block's bits. Filament derives both from
  beacon headers it verified (`GET /chain/header-proof/{from}`), never from a Keystone's word.

Only shards listed in the genesis (`initial_shard_count`) can be followed this way. A shard opened
later by an expand vote cannot be verified yet (below).

## Invoice confirmation

`Confirmed` needs all of:

1. the shard's thin state is `synced` (a fresh quorum on a state Filament checked block by block);
2. the paying block is at least `confirmation_depth` (default 6) below Filament's own verified tip;
3. the paying block is bound to Filament's verified shard chain: the stored inclusion proof verifies
   against the shard anchor, and the leaf it names equals the leaf Filament recomputed from the held
   record, or the leaf in a fresh range proof for that height;
4. the paying **output** is proved inside that block: a `TxInclusionProof` against the block's
   `tx_merkle_root` (`GET /shard/{id}/tx-proof?height=&output_idx=`), and the output pays the
   invoice's recipient at least its amount.

The invoice then carries `assurance`:

| `assurance` | Meaning |
|---|---|
| `verified_chain` | All four conditions on a shard chain Filament verified. Strongest. |
| `keystone_quorum` | A dynamic shard: depth from a quorum of Keystone-reported tips and the payment proved by a quorum of Keystones. |
| `keystone_tip` | Thin sync off: depth from Keystone-reported tips, no payment proof. Weakest. |

## Reading the status

`GET /sync/status` and `GET /chain/shard/{id}` report a phase per chain:

| Phase | Meaning |
|---|---|
| `bootstrapping` | No verified state yet. Check `--network` / `--genesis-file` match the Keystones, and that at least two answer. |
| `synced` | A fresh quorum on a verified state (the last round was under 90 s ago). |
| `insufficient_peers` | Fewer Keystones answered than the quorum needs. Add `--keystone-extra`, or `--allow-single-keystone` on a dev setup. |
| `unsupported` | A dynamic shard. Confirmations carry `keystone_quorum` assurance. |

`Invalid chain summary proof` almost always means the wrong network: the Bitcoin anchor in the genesis
differs per network.

## Measured sizes

JSON bytes, one response each, on small test chains:

| | Tip poll | Session | One new block | Old full summary |
|---|---|---|---|---|
| Beacon, 120 to 10,000 blocks | 109–112 B | 7.5–7.8 KB | 346–349 B | 134–159 KB |
| Shard, 120 to 1,000 blocks | 109–110 B | 10.6–11 KB | 539–548 B | 162–166 KB |

The session size does not grow with the chain (a range proof over 16 leaves). These are single
responses; they have not been re-measured on a live fleet.

## Limits

* The work check covers the work a header **claims**, not that it equals the difficulty adjustment's
  expected value. Comparing Keystones is what rejects a cheap fake chain.
* A shard record's chain count is the miner's claim; it is checked against its own sibling path and the
  admissible range for the epoch the block's height maps to.
* A proved output is in the block. That the transaction is valid rests on the chain's proof of work.
* **Dynamic shards** are not verified (the true active chain count cannot be derived from verified
  headers alone). Two fixes are under consideration, neither implemented: replay the expand votes in
  the client, or commit the exact count in the header. Until then they carry the lower assurance above.
* The beacon and shard states have not run against a live fleet yet, and the push model (new headers
  pushed over P2P, the 30 s loop only a keep-alive) is not built.
