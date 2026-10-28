//! Reject policy requirements the Docker-capable runtime cannot enforce.
//!
//! Validation understands intent only. It neither installs runtime controls nor
//! authorizes creation or readiness. A hardened caller must separately require
//! verified VM, storage, and external network fences for the current generation.

use std::fmt;

use crate::proto::openshell::sandbox::v1::{FilesystemPolicy, ProcessPolicy, SandboxPolicy};

const SUPPORTED_POLICY_VERSION: u32 = 1;

/// Policy intent understood by this validator, without enforcement evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "policy validation does not authorize execution or readiness"]
pub struct ValidatedPolicy(());

/// A guest filesystem clause that requires enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemField {
    ReadOnly,
    ReadWrite,
    Workdir,
}

impl fmt::Display for FilesystemField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReadOnly => "filesystem.read_only",
            Self::ReadWrite => "filesystem.read_write",
            Self::Workdir => "filesystem.include_workdir",
        })
    }
}

/// A process identity selector the runtime would need to honor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessField {
    User,
    Group,
}

impl fmt::Display for ProcessField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::User => "process.run_as_user",
            Self::Group => "process.run_as_group",
        })
    }
}

/// Why a path is outside the accepted, unambiguous POSIX syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRejection {
    NotAbsolute,
    RootDirectory,
    NonCanonical,
    NonPosix,
    ControlCharacter,
}

impl fmt::Display for PathRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotAbsolute => "path must be absolute",
            Self::RootDirectory => "unrestricted root paths are not supported",
            Self::NonCanonical => "path contains an empty, dot, or parent component",
            Self::NonPosix => "path must use POSIX separators",
            Self::ControlCharacter => "path contains a control character",
        })
    }
}

/// An explicit guarantee for which runtime enforcement is not implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyFeature {
    GuestFilesystem(FilesystemField),
    GuestLandlock,
    ProcessIdentity(ProcessField),
    GuestBinaryIdentity,
    NetworkAccess,
    NetworkMiddleware,
}

impl fmt::Display for PolicyFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GuestFilesystem(field) => write!(f, "{field} guest-path enforcement"),
            Self::GuestLandlock => f.write_str("guest Landlock enforcement"),
            Self::ProcessIdentity(field) => write!(f, "{field} identity enforcement"),
            Self::GuestBinaryIdentity => f.write_str("guest executable identity enforcement"),
            Self::NetworkAccess => f.write_str("external network policy enforcement"),
            Self::NetworkMiddleware => f.write_str("network middleware enforcement"),
        }
    }
}

/// A rejected policy requirement, without user-supplied paths or secret values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    UnsupportedVersion(u32),
    InvalidPath {
        field: FilesystemField,
        reason: PathRejection,
    },
    InvalidLandlockMode,
    InvalidProcessIdentity(ProcessField),
    InvalidNetworkRule,
    Unsupported(PolicyFeature),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => write!(f, "unsupported policy version {version}"),
            Self::InvalidPath { field, reason } => write!(f, "invalid {field}: {reason}"),
            Self::InvalidLandlockMode => f.write_str("invalid landlock compatibility mode"),
            Self::InvalidProcessIdentity(field) => write!(f, "invalid non-root {field} selector"),
            Self::InvalidNetworkRule => {
                f.write_str("network rule requires endpoints and executable selectors")
            }
            Self::Unsupported(feature) => write!(f, "unsupported policy requirement: {feature}"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Validate policy intent without claiming that runtime controls exist.
///
/// Guest-root Docker can defeat guest-local path, process, and executable
/// restrictions. The validator rejects those guarantees instead of weakening
/// them. Even an accepted policy still requires independent runtime admission.
///
/// # Errors
/// Returns a typed error for unsupported versions, ambiguous paths or identities,
/// and every requested enforcement feature not implemented by this runtime.
pub fn validate_policy(policy: &SandboxPolicy) -> Result<ValidatedPolicy, PolicyError> {
    if policy.version != SUPPORTED_POLICY_VERSION {
        return Err(PolicyError::UnsupportedVersion(policy.version));
    }
    if let Some(filesystem) = &policy.filesystem {
        validate_filesystem(filesystem)?;
    }
    if let Some(landlock) = &policy.landlock {
        if !matches!(
            landlock.compatibility.as_str(),
            "" | "best_effort" | "hard_requirement"
        ) {
            return Err(PolicyError::InvalidLandlockMode);
        }
        return Err(PolicyError::Unsupported(PolicyFeature::GuestLandlock));
    }
    if let Some(process) = &policy.process {
        validate_process(process)?;
    }
    validate_network(policy)?;
    Ok(ValidatedPolicy(()))
}

fn validate_filesystem(filesystem: &FilesystemPolicy) -> Result<(), PolicyError> {
    for (paths, field) in [
        (&filesystem.read_only, FilesystemField::ReadOnly),
        (&filesystem.read_write, FilesystemField::ReadWrite),
    ] {
        for path in paths {
            validate_path(path).map_err(|reason| PolicyError::InvalidPath { field, reason })?;
        }
    }
    let requirement = if filesystem.include_workdir {
        Some(FilesystemField::Workdir)
    } else if !filesystem.read_only.is_empty() {
        Some(FilesystemField::ReadOnly)
    } else if !filesystem.read_write.is_empty() {
        Some(FilesystemField::ReadWrite)
    } else {
        None
    };
    if let Some(field) = requirement {
        return Err(PolicyError::Unsupported(PolicyFeature::GuestFilesystem(
            field,
        )));
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), PathRejection> {
    if !path.starts_with('/') {
        return Err(PathRejection::NotAbsolute);
    }
    if path == "/" {
        return Err(PathRejection::RootDirectory);
    }
    if path.chars().any(char::is_control) {
        return Err(PathRejection::ControlCharacter);
    }
    if path.contains('\\') {
        return Err(PathRejection::NonPosix);
    }
    if path[1..]
        .split('/')
        .any(|component| matches!(component, "" | "." | ".."))
    {
        return Err(PathRejection::NonCanonical);
    }
    Ok(())
}

fn validate_process(process: &ProcessPolicy) -> Result<(), PolicyError> {
    let selectors = [
        (process.run_as_user.as_str(), ProcessField::User),
        (process.run_as_group.as_str(), ProcessField::Group),
    ];
    for (selector, field) in selectors {
        if !selector.is_empty() && !valid_identity_selector(selector) {
            return Err(PolicyError::InvalidProcessIdentity(field));
        }
    }
    if let Some((_, field)) = selectors.iter().find(|(selector, _)| !selector.is_empty()) {
        return Err(PolicyError::Unsupported(PolicyFeature::ProcessIdentity(
            *field,
        )));
    }
    Ok(())
}

fn valid_identity_selector(selector: &str) -> bool {
    if selector == "root" {
        return false;
    }
    if selector.bytes().all(|byte| byte.is_ascii_digit()) {
        return selector.parse::<u32>().is_ok_and(|id| id != 0);
    }
    selector.starts_with(|first: char| first.is_ascii_alphabetic() || first == '_')
        && selector
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn validate_network(policy: &SandboxPolicy) -> Result<(), PolicyError> {
    if !policy.network_middlewares.is_empty() {
        return Err(PolicyError::Unsupported(PolicyFeature::NetworkMiddleware));
    }
    if policy
        .network_policies
        .values()
        .any(|rule| rule.binaries.is_empty() || rule.endpoints.is_empty())
    {
        return Err(PolicyError::InvalidNetworkRule);
    }
    if policy
        .network_policies
        .values()
        .any(|rule| rule.binaries.iter().any(|binary| binary.path != "/**"))
    {
        return Err(PolicyError::Unsupported(PolicyFeature::GuestBinaryIdentity));
    }
    if !policy.network_policies.is_empty() {
        return Err(PolicyError::Unsupported(PolicyFeature::NetworkAccess));
    }
    Ok(())
}
