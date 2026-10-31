//! filament-p2p — minimal ShishaNet P2P client for the Filament light
//! client. Clean-room reimplementation of only what a light client needs:
//! dial, handshake, `WatchAddress`, and the three Path-2 notification
//! message types. Not the real `PeerManager` — no sync engine, no mempool
//! sync, no DoS/eclipse protection, no addr book. See `peer_manager.rs`'s
//! own doc comment.

pub mod framing;
pub mod messages;
pub mod tip_identity;
pub mod pow_validator;
pub mod peer_manager;

pub use framing::{magic_bytes_for_network, magic_for_network};
pub use messages::{
    NetAddr, ShishaMessage, VersionMessage, GENESIS_HASH_LEN, MIN_ACCEPTED_VERSION, UNKNOWN_GENESIS_HASH, WIRE_VERSION,
};
pub use peer_manager::{
    Capabilities, LightClientInboundNotif, PeerManager, ShishaProtocol, NODE_LIGHT, NODE_NETWORK,
};

/// Path-compatibility shim: exposes this crate under the module layout
/// (`p2p_proto::p2p::common::manager::PeerManager`, etc.) that `filament`'s
/// source imports, so it compiles unchanged against this one.
pub mod p2p {
    pub mod common {
        pub mod pow_validator {
            pub use crate::pow_validator::*;
        }
        pub mod manager {
            pub use crate::peer_manager::PeerManager;
        }
        pub mod traits {
            pub use crate::peer_manager::{Capabilities, LightClientInboundNotif, NODE_LIGHT, NODE_NETWORK};
        }
    }
    pub mod shishanet {
        pub use crate::messages::ShishaMessage;
        pub use crate::peer_manager::ShishaProtocol;
    }
}
