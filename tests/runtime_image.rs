use openshell_kata::runtime::model::{selected_image, verify_image};
use serde_json::json;

#[test]
fn legacy_image_remains_an_explicit_operator_default() {
    assert_eq!(
        selected_image(None).expect("default local image"),
        "docker.io/library/openshell-kata-enforced:local"
    );
}

#[test]
fn pinned_image_is_exact_and_invalid_references_fail_closed() {
    let image = format!("registry.example/guest@sha256:{}", "a".repeat(64));
    assert_eq!(
        selected_image(Some(&image)).expect("valid operator image"),
        image
    );
    for bad in [
        "registry.example/guest:latest",
        "",
        "@sha256:123",
        "registry.example/guest@sha256:abc",
    ] {
        assert!(
            selected_image(Some(bad)).is_err(),
            "invalid reference {bad:?}"
        );
    }
}

#[test]
fn runtime_observation_must_match_the_admitted_image() {
    let image = format!("registry.example/guest@sha256:{}", "b".repeat(64));
    assert!(verify_image(&json!({"Image": image}), &image).is_ok());
    assert!(verify_image(&json!({"Image": "another-image"}), &image).is_err());
    assert!(verify_image(&json!({}), &image).is_err());
}
