//! filament-p2p — minimal ShishaNet P2P client for the Filament light
//! client. Clean-room reimplementation of only what a light client needs:
//! dial, handshake, `WatchAddress`, and the three Path-2 notification
//! message types. Not the real `PeerManager` — no sync engine, no mempool
//! sync, no DoS/eclipse protection, no addr book. See `peer_manager.rs`'s
//! own doc comment.

pub mod framing;
pub mod messages;
pub mod peer_manager;

pub use messages::ShishaMessage;
pub use peer_manager::{
    Capabilities, LightClientInboundNotif, PeerManager, ShishaProtocol, NODE_LIGHT, NODE_NETWORK,
};

/// Path-compatibility shim matching the private monorepo's `p2p-proto`
/// module layout (`p2p_proto::p2p::common::manager::PeerManager`, etc.) so
/// `filament`'s own source, written against that crate, compiles unchanged
/// against this one.
pub mod p2p {
    pub mod common {
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
