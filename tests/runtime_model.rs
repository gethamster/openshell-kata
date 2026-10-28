use openshell_kata::runtime::model::{Action, confirmed_absent, guest_address, validate_nonce};
use serde_json::json;

#[test]
fn actions_remain_compatible_and_reject_unknown_values() {
    assert_eq!(
        "create".parse::<Action>().expect("valid test fixture"),
        Action::Create
    );
    assert_eq!(
        "verify".parse::<Action>().expect("valid test fixture"),
        Action::Verify
    );
    assert!("launch-shell".parse::<Action>().is_err());
}
#[test]
fn a_single_real_network_address_is_selected_in_presence_of_kata_tap() {
    let info = json!({"NetworkSettings":{"Networks":{"unknown-tap":{"IPAddress":""},"eth0":{"IPAddress":"10.203.1.2"}}}});
    assert_eq!(
        guest_address(&info)
            .expect("valid test fixture")
            .to_string(),
        "10.203.1.2"
    );
    assert!(guest_address(&json!({"NetworkSettings":{"Networks":{}}})).is_err());
}
#[test]
fn absence_requires_the_exact_object_and_no_transport_error() {
    assert!(confirmed_absent(
        1,
        b"",
        b"time=\"now\" level=fatal msg=\"1 errors: [no such object one]\"\n",
        "one"
    ));
    assert!(!confirmed_absent(1, b"", b"connection refused", "one"));
    assert!(!confirmed_absent(
        1,
        b"",
        b"level=fatal msg=\"1 errors: [no such object other]\"",
        "one"
    ));
}
#[test]
fn nonce_is_bounded_ascii_and_not_a_path() {
    assert!(validate_nonce("a1234567890123456").is_ok());
    for bad in ["", "../../bad", "has a space 123456789"] {
        assert!(validate_nonce(bad).is_err());
    }
}
