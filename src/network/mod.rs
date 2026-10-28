//! An external guest egress fence and an explicit TCP destination broker.
mod broker;
mod cli;
mod fence;
mod policy;
mod proxy;

pub use broker::{BrokerHandle, bind_broker};
pub use cli::{NetworkCli, run_network};
pub use fence::{FenceProof, FenceSpec, install_fence, remove_fence, verify_fence};
pub use policy::{
    Endpoint, NetworkPolicy, ValidatedNetworkPolicy, globally_routable, normalize_host,
};
