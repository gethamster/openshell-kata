//! Guest-side command and file conveniences, separate from the external VM boundary.

mod files;
mod process;

pub use files::{RemoveOptions, Workspace};
pub use process::{kill, run, run_child};

/// Maximum bytes in one System file operation.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
