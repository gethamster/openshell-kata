//! Official-shim stand-in used only for a preboot execution-order assertion.
fn main() -> std::io::Result<()> {
    std::fs::write(
        "/tmp/guard-shim-started",
        std::env::args().collect::<Vec<_>>().join("\n"),
    )
}
