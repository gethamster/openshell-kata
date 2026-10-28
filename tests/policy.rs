use openshell_kata::policy::{
    FilesystemField, PathRejection, PolicyError, PolicyFeature, ProcessField, validate_policy,
};
use openshell_kata::proto::openshell::sandbox::v1::{
    FilesystemPolicy, LandlockPolicy, NetworkBinary, NetworkEndpoint, NetworkMiddlewareConfig,
    NetworkPolicyRule, ProcessPolicy, SandboxPolicy,
};

fn unconstrained_guest_policy() -> SandboxPolicy {
    SandboxPolicy {
        version: 1,
        ..SandboxPolicy::default()
    }
}

fn network_policy(binary: &str) -> SandboxPolicy {
    SandboxPolicy {
        network_policies: [(
            "network".to_owned(),
            NetworkPolicyRule {
                binaries: vec![NetworkBinary {
                    path: binary.to_owned(),
                }],
                endpoints: vec![NetworkEndpoint {
                    host: "example.com".to_owned(),
                    port: 443,
                    ..NetworkEndpoint::default()
                }],
                ..NetworkPolicyRule::default()
            },
        )]
        .into(),
        ..unconstrained_guest_policy()
    }
}

#[test]
fn validates_intent_without_claiming_runtime_enforcement() {
    let policy = unconstrained_guest_policy();
    let original = policy.clone();
    assert!(validate_policy(&policy).is_ok());
    assert_eq!(policy, original, "validation must not rewrite policy");
}

#[test]
fn absent_version_and_future_versions_are_rejected() {
    for version in [0, 2, u32::MAX] {
        let policy = SandboxPolicy {
            version,
            ..SandboxPolicy::default()
        };
        assert_eq!(
            validate_policy(&policy),
            Err(PolicyError::UnsupportedVersion(version)),
        );
    }
}

#[test]
fn rejects_guest_filesystem_promises_that_rootful_docker_can_bypass() {
    for (read_only, read_write, feature) in [
        (vec!["/usr".to_owned()], vec![], FilesystemField::ReadOnly),
        (
            vec![],
            vec!["/sandbox".to_owned()],
            FilesystemField::ReadWrite,
        ),
    ] {
        let policy = SandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                read_only,
                read_write,
                ..FilesystemPolicy::default()
            }),
            ..unconstrained_guest_policy()
        };
        assert_eq!(
            validate_policy(&policy),
            Err(PolicyError::Unsupported(PolicyFeature::GuestFilesystem(
                feature
            ))),
        );
    }
}

#[test]
fn rejects_path_ambiguity_without_returning_the_supplied_path() {
    for (path, reason) in [
        ("", PathRejection::NotAbsolute),
        ("relative/private-token", PathRejection::NotAbsolute),
        ("C:\\private-token", PathRejection::NotAbsolute),
        ("/", PathRejection::RootDirectory),
        ("/sandbox/../private-token", PathRejection::NonCanonical),
        ("/sandbox/./private-token", PathRejection::NonCanonical),
        ("/sandbox//private-token", PathRejection::NonCanonical),
        ("/sandbox\\private-token", PathRejection::NonPosix),
        ("/sandbox/\0private-token", PathRejection::ControlCharacter),
    ] {
        let policy = SandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                read_write: vec![path.to_owned()],
                ..FilesystemPolicy::default()
            }),
            ..unconstrained_guest_policy()
        };
        let error = validate_policy(&policy).expect_err("path must be rejected");
        assert_eq!(
            error,
            PolicyError::InvalidPath {
                field: FilesystemField::ReadWrite,
                reason,
            }
        );
        assert!(!error.to_string().contains("private-token"));
    }
}

#[test]
fn validates_every_path_before_reporting_unsupported_filesystem_semantics() {
    let policy = SandboxPolicy {
        filesystem: Some(FilesystemPolicy {
            read_only: vec!["/usr".to_owned()],
            read_write: vec!["relative".to_owned()],
            ..FilesystemPolicy::default()
        }),
        ..unconstrained_guest_policy()
    };
    assert_eq!(
        validate_policy(&policy),
        Err(PolicyError::InvalidPath {
            field: FilesystemField::ReadWrite,
            reason: PathRejection::NotAbsolute,
        })
    );
}

#[test]
fn include_workdir_is_an_unsupported_filesystem_promise() {
    let policy = SandboxPolicy {
        filesystem: Some(FilesystemPolicy {
            include_workdir: true,
            ..FilesystemPolicy::default()
        }),
        ..unconstrained_guest_policy()
    };
    assert_eq!(
        validate_policy(&policy),
        Err(PolicyError::Unsupported(PolicyFeature::GuestFilesystem(
            FilesystemField::Workdir
        ),))
    );
}

#[test]
fn does_not_report_guest_landlock_as_honored() {
    for mode in ["", "best_effort", "hard_requirement"] {
        let policy = SandboxPolicy {
            landlock: Some(LandlockPolicy {
                compatibility: mode.to_owned(),
            }),
            ..unconstrained_guest_policy()
        };
        assert_eq!(
            validate_policy(&policy),
            Err(PolicyError::Unsupported(PolicyFeature::GuestLandlock,))
        );
    }
    let policy = SandboxPolicy {
        landlock: Some(LandlockPolicy {
            compatibility: "ignore-all".to_owned(),
        }),
        ..unconstrained_guest_policy()
    };
    assert_eq!(
        validate_policy(&policy),
        Err(PolicyError::InvalidLandlockMode)
    );
}

#[test]
fn rejects_unimplemented_identity_selectors_and_invalid_identities() {
    for (selector, invalid) in [
        ("root", true),
        ("0", true),
        ("000", true),
        ("-1", true),
        ("4294967296", true),
        ("1000:1000", true),
        (" sandbox", true),
        ("1000", false),
        ("sandbox", false),
        ("alice", false),
    ] {
        for field in [ProcessField::User, ProcessField::Group] {
            let process = match field {
                ProcessField::User => ProcessPolicy {
                    run_as_user: selector.to_owned(),
                    ..ProcessPolicy::default()
                },
                ProcessField::Group => ProcessPolicy {
                    run_as_group: selector.to_owned(),
                    ..ProcessPolicy::default()
                },
            };
            let policy = SandboxPolicy {
                process: Some(process),
                ..unconstrained_guest_policy()
            };
            let expected = if invalid {
                PolicyError::InvalidProcessIdentity(field)
            } else {
                PolicyError::Unsupported(PolicyFeature::ProcessIdentity(field))
            };
            assert_eq!(
                validate_policy(&policy),
                Err(expected),
                "selector {selector}"
            );
        }
    }
}

#[test]
fn does_not_treat_guest_binary_identity_as_authoritative() {
    for binary in ["/usr/bin/curl", "/usr/bin/**", ""] {
        assert_eq!(
            validate_policy(&network_policy(binary)),
            Err(PolicyError::Unsupported(PolicyFeature::GuestBinaryIdentity,))
        );
    }
}

#[test]
fn all_executables_does_not_enable_unimplemented_network_enforcement() {
    assert_eq!(
        validate_policy(&network_policy("/**")),
        Err(PolicyError::Unsupported(PolicyFeature::NetworkAccess,))
    );
}

#[test]
fn rejects_even_empty_network_rules_instead_of_silently_dropping_them() {
    let policy = SandboxPolicy {
        network_policies: [("empty".to_owned(), NetworkPolicyRule::default())].into(),
        ..unconstrained_guest_policy()
    };
    assert_eq!(
        validate_policy(&policy),
        Err(PolicyError::InvalidNetworkRule)
    );
}

#[test]
fn credential_and_l7_fields_never_get_silently_accepted_or_logged() {
    let policy = SandboxPolicy {
        network_policies: [(
            "network".to_owned(),
            NetworkPolicyRule {
                binaries: vec![NetworkBinary {
                    path: "/**".to_owned(),
                }],
                endpoints: vec![NetworkEndpoint {
                    host: "example.com".to_owned(),
                    port: 443,
                    protocol: "rest".to_owned(),
                    credential_signing: "private-token".to_owned(),
                    provider_credentialed: true,
                    ..NetworkEndpoint::default()
                }],
                ..NetworkPolicyRule::default()
            },
        )]
        .into(),
        ..unconstrained_guest_policy()
    };
    let error = validate_policy(&policy).expect_err("network is not implemented");
    assert_eq!(
        error,
        PolicyError::Unsupported(PolicyFeature::NetworkAccess)
    );
    assert!(!error.to_string().contains("private-token"));
}

#[test]
fn rejects_middleware_without_claiming_to_execute_it() {
    let policy = SandboxPolicy {
        network_middlewares: [(
            "content-guard".to_owned(),
            NetworkMiddlewareConfig::default(),
        )]
        .into(),
        ..unconstrained_guest_policy()
    };
    assert_eq!(
        validate_policy(&policy),
        Err(PolicyError::Unsupported(PolicyFeature::NetworkMiddleware,))
    );
}
