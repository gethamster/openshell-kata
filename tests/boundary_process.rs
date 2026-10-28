use openshell_kata::boundary::process::{OperatorCeilings, VmLimits};

#[test]
fn validates_each_limit_and_rejects_unknown_fields() {
    let limits = VmLimits {
        vcpus: 2,
        memory_mib: 2048,
        disk_mib: 8192,
        lifetime_secs: 120,
    };
    let ceilings = OperatorCeilings {
        vcpus: 4,
        memory_mib: 4096,
        disk_mib: 16384,
        lifetime_secs: 3600,
    };
    assert_eq!(
        limits.validate(&ceilings).expect("valid").as_limits(),
        &limits
    );
    for limits in [
        VmLimits { vcpus: 0, ..limits },
        VmLimits {
            memory_mib: 0,
            ..limits
        },
        VmLimits {
            disk_mib: 0,
            ..limits
        },
        VmLimits {
            lifetime_secs: 0,
            ..limits
        },
        VmLimits { vcpus: 5, ..limits },
        VmLimits {
            memory_mib: 4097,
            ..limits
        },
        VmLimits {
            disk_mib: 16385,
            ..limits
        },
        VmLimits {
            lifetime_secs: 3601,
            ..limits
        },
    ] {
        assert!(limits.validate(&ceilings).is_err());
    }
    assert!(
        serde_json::from_str::<VmLimits>(
            r#"{"vcpus":2,"memory_mib":2048,"disk_mib":8192,"lifetime_secs":120,"process_count":5}"#
        )
        .is_err()
    );
}

#[test]
fn deadline_is_checked_and_expiration_includes_boundary() {
    let limits = VmLimits {
        vcpus: 2,
        memory_mib: 2048,
        disk_mib: 8192,
        lifetime_secs: 120,
    }
    .validate(&OperatorCeilings::default())
    .expect("valid");
    let deadline = limits.deadline_from(1000).expect("deadline");
    assert_eq!(deadline.expires_at_unix_secs(), 1120);
    assert!(!deadline.expired_at(1119));
    assert!(deadline.expired_at(1120));
    assert!(deadline.expired_at(999), "clock rollback fails closed");
    assert!(limits.deadline_from(u64::MAX).is_err());
    assert_eq!(limits.memory_bytes(), 2048 * 1024 * 1024);
    assert_eq!(limits.disk_bytes(), 8192 * 1024 * 1024);
}

#[test]
fn detects_byte_count_overflow_and_invalid_persisted_deadline() {
    use openshell_kata::boundary::process::VmDeadline;
    let ceilings = OperatorCeilings {
        vcpus: 1,
        memory_mib: u64::MAX,
        disk_mib: u64::MAX,
        lifetime_secs: u64::MAX,
    };
    assert!(
        VmLimits {
            vcpus: 1,
            memory_mib: u64::MAX,
            disk_mib: 1,
            lifetime_secs: 1
        }
        .validate(&ceilings)
        .is_err()
    );
    assert!(
        VmLimits {
            vcpus: 1,
            memory_mib: 1,
            disk_mib: u64::MAX,
            lifetime_secs: 1
        }
        .validate(&ceilings)
        .is_err()
    );
    let invalid: VmDeadline =
        serde_json::from_str(r#"{"started_at_unix_secs":12,"expires_at_unix_secs":11}"#)
            .expect("decode");
    assert!(invalid.expired_at(10));
    assert!(invalid.expired_at(12));
}
