//! P2P network identity: per-network framing magic + genesis chain identity.
//!
//! **Single source of truth** for the 4-byte "magic" that prefixes every P2P
//! frame, for both P2P protocols. Two layers of identity:
//!
//! 1. **Network magic (per network family, framing layer).** Every frame
//!    starts with 4 magic bytes; a receiver drops the connection on the first
//!    frame whose magic differs from its own (`"Wrong network magic"`). This
//!    cheaply separates mainnet / testnets / devnet traffic before any message
//!    is parsed. Keyed by the P2P config's `network` name
//!    (`[shishanet] network = "..."`).
//! 2. **Genesis hash (per chain, handshake layer).** Two different chains can
//!    share a network name (e.g. every soak genesis runs as `devnet`). The
//!    ShishaNet handshake (wire v11+) therefore also carries the beacon
//!    genesis block hash ([`super::GenesisGenerator::beacon_genesis_hash`]);
//!    a peer advertising a different non-zero genesis hash is refused.
//!
//! BV-PROTO-1 §7 VF-6/VF-7 (`docs/plan/BV_PROTO_1_Block_Versioning_Research.md`).
//! Before this module existed every ShishaNet node on every network used one
//! constant magic (`0x53484254`), and the Lattice stub used **Bitcoin's own**
//! mainnet/testnet magics.
//!
//! ## Canonical values (wire bytes, in the order they appear on the wire)
//!
//! | Network name      | ShishaNet | Lattice (stub) |
//! |-------------------|-----------|----------------|
//! | `mainnet`         | `SHMN`    | `LTMN`         |
//! | `testnet1`        | `SHT1`    | `LTT1`         |
//! | `testnet2`        | `SHT2`    | `LTT2`         |
//! | `devnet`          | `SHDV`    | `LTDV`         |
//! | `testnet-stress`  | `SHTS`    | `LTTS`         |
//! | anything else     | `SX` + 2 B | `LX` + 2 B    |
//!
//! "Anything else": the last two bytes are the first two bytes of
//! `BLAKE3("shisha-p2p-magic:" ‖ protocol ‖ ":" ‖ name)`, so a custom network
//! name gets its own stable magic without a table entry. The `SX`/`LX` prefix
//! keeps derived magics from ever colliding with a named entry.
//!
//! On the wire the magic is the 4 bytes above; in code it is
//! `u32::from_le_bytes(bytes)` (frames encode the magic little-endian).
//!
//! **Changing any value here is a network-breaking change** — every node on
//! that network must be rebuilt together. Keep `docs/plan/P2P_Network_Identity.md`
//! (the operator/wiki-facing copy of this table) in sync.

/// P2P protocol a magic is being derived for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P2pProtocolKind {
    /// ShishaNet — the production protocol (`[shishanet]`).
    ShishaNet,
    /// Lattice — the deliberately unbranded experimental stub (`[lattice]`).
    Lattice,
}

impl P2pProtocolKind {
    fn tag(self) -> &'static str {
        match self {
            Self::ShishaNet => "shishanet",
            Self::Lattice => "lattice",
        }
    }
}

/// Wire bytes of the framing magic for `network` on `protocol`.
///
/// See the module docs for the canonical table.
pub fn p2p_network_magic_bytes(protocol: P2pProtocolKind, network: &str) -> [u8; 4] {
    let suffix: Option<&[u8; 2]> = match network {
        "mainnet" => Some(b"MN"),
        "testnet1" => Some(b"T1"),
        "testnet2" => Some(b"T2"),
        "devnet" => Some(b"DV"),
        "testnet-stress" => Some(b"TS"),
        _ => None,
    };
    match (protocol, suffix) {
        (P2pProtocolKind::ShishaNet, Some(s)) => [b'S', b'H', s[0], s[1]],
        (P2pProtocolKind::Lattice, Some(s)) => [b'L', b'T', s[0], s[1]],
        (_, None) => {
            let mut h = blake3::Hasher::new();
            h.update(b"shisha-p2p-magic:");
            h.update(protocol.tag().as_bytes());
            h.update(b":");
            h.update(network.as_bytes());
            let d = h.finalize();
            let d = d.as_bytes();
            let prefix = match protocol {
                P2pProtocolKind::ShishaNet => b'S',
                P2pProtocolKind::Lattice => b'L',
            };
            [prefix, b'X', d[0], d[1]]
        }
    }
}

/// Framing magic for `network` on `protocol`, as the `u32` the framing codec
/// compares (`u32::from_le_bytes` of [`p2p_network_magic_bytes`]).
pub fn p2p_network_magic(protocol: P2pProtocolKind, network: &str) -> u32 {
    u32::from_le_bytes(p2p_network_magic_bytes(protocol, network))
}

/// Genesis hash advertised by a node that does not know (or does not check)
/// its chain's genesis — e.g. a light client. Never compared against.
pub const UNKNOWN_GENESIS_HASH: [u8; 32] = [0u8; 32];

#[cfg(test)]
mod tests {
    use super::*;

    const NAMED: [&str; 5] = ["mainnet", "testnet1", "testnet2", "devnet", "testnet-stress"];

    #[test]
    fn named_networks_have_the_documented_bytes() {
        use P2pProtocolKind::*;
        assert_eq!(&p2p_network_magic_bytes(ShishaNet, "mainnet"), b"SHMN");
        assert_eq!(&p2p_network_magic_bytes(ShishaNet, "testnet1"), b"SHT1");
        assert_eq!(&p2p_network_magic_bytes(ShishaNet, "testnet2"), b"SHT2");
        assert_eq!(&p2p_network_magic_bytes(ShishaNet, "devnet"), b"SHDV");
        assert_eq!(&p2p_network_magic_bytes(ShishaNet, "testnet-stress"), b"SHTS");
        assert_eq!(&p2p_network_magic_bytes(Lattice, "mainnet"), b"LTMN");
        assert_eq!(&p2p_network_magic_bytes(Lattice, "devnet"), b"LTDV");
    }

    #[test]
    fn every_magic_is_distinct_across_networks_and_protocols() {
        let mut all = std::collections::HashSet::new();
        for p in [P2pProtocolKind::ShishaNet, P2pProtocolKind::Lattice] {
            for n in NAMED.iter().copied().chain(["custom", "devnet_15", "testnet"]) {
                assert!(all.insert(p2p_network_magic(p, n)), "duplicate magic for {p:?}/{n}");
            }
        }
    }

    #[test]
    fn derived_magics_are_stable_and_prefixed() {
        let a = p2p_network_magic_bytes(P2pProtocolKind::ShishaNet, "my-private-net");
        let b = p2p_network_magic_bytes(P2pProtocolKind::ShishaNet, "my-private-net");
        assert_eq!(a, b);
        assert_eq!(&a[..2], b"SX");
        assert_eq!(&p2p_network_magic_bytes(P2pProtocolKind::Lattice, "x")[..2], b"LX");
    }

    #[test]
    fn no_magic_is_bitcoins_or_the_old_shared_constant() {
        // Bitcoin mainnet / testnet3 / regtest magics, and the pre-VF-7
        // shared ShishaNet constant 0x53484254.
        let forbidden = [0xD9B4BEF9u32, 0x0709110B, 0xDAB5BFFA, 0x53484254];
        for p in [P2pProtocolKind::ShishaNet, P2pProtocolKind::Lattice] {
            for n in NAMED {
                assert!(!forbidden.contains(&p2p_network_magic(p, n)), "{p:?}/{n}");
            }
        }
    }

    /// The P2P chain identity is the genesis block's plain PoW hash — the same
    /// value `expected_hash` pins — and it separates chains that share a name.
    ///
    /// Uses the shipped `config/genesis_testnet_stress.toml`, which pins
    /// `expected_hash` (in weighted form).
    #[test]
    fn genesis_hash_identity_matches_pinned_expected_hash_and_separates_chains() {
        use super::super::{GenesisGenerator, NetworkGenesisConfig, BeaconGenesisConfig};
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/genesis_testnet_stress.toml");
        let ts = NetworkGenesisConfig::from_file(&path).expect("shipped genesis parses").beacon;
        let h = GenesisGenerator::beacon_genesis_hash(&ts).expect("shipped genesis generates");
        if let Some(pinned) = ts.expected_hash {
            assert_eq!(h, pinned, "identity must equal the pinned genesis hash");
        }
        assert_eq!(h, GenesisGenerator::beacon_genesis_hash(&ts).unwrap(), "deterministic");
        let dev = GenesisGenerator::beacon_genesis_hash(&BeaconGenesisConfig::devnet()).unwrap();
        assert_ne!(h, dev, "different genesis ⇒ different identity");
        assert_ne!(h, UNKNOWN_GENESIS_HASH);
    }
}
