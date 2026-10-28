//! Trusted preboot wrapper for the upstream Kata containerd shim.
fn main() -> anyhow::Result<()> {
    openshell_kata::network::hosted_fence::run_runtime_guard()
}
