//! Host-enforced boundaries for guests that are allowed to run Docker as root.
//!
//! Guest root is not a filesystem or process policy boundary. These modules
//! constrain transfers and the VM resources controlled by the trusted runtime.
pub mod filesystem;
pub mod process;
