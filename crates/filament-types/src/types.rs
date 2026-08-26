// filament-types/src/types.rs

use std::fmt;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainType {
    Beacon,
    Shard,
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainType::Beacon => write!(f, "Beacon"),
            ChainType::Shard => write!(f, "Shard"),
        }
    }
}
