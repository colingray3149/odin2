use super::fixture::fixture_context;
use super::*;

use crate::live::rollover::{RolloverPolicy, RolloverRuntimeConfig};

/// Each row breaks one field of an otherwise valid configuration; the bridge
/// refuses it before any lease, row or process exists.
#[tokio::test]
async fn a_configuration_with_one_broken_field_is_refused_by_kind() {
    type Break = fn(&mut OmpBridgeConfig);
    let root = tempfile::tempdir().unwrap();
    let context = fixture_context(root.path(), 1, "config-validate").await;
    let valid = context.bridge_config(context.session_descriptor()).unwrap();
    valid
        .validate()
        .expect("the fixture configuration is valid");
    let rows: [(&str, Break, bool); 7] = [
        (
            "another session",
            |config| config.binding.session_id = SessionId::new("session:other").unwrap(),
            true,
        ),
        (
            "blank owner",
            |config| config.binding.owner_id = " ".to_owned(),
            true,
        ),
        ("pre-set epoch", |config| config.binding.epoch = 3, true),
        (
            "zero lease ttl",
            |config| config.lease_ttl = Duration::ZERO,
            false,
        ),
        (
            "empty artifact root",
            |config| config.artifact_root = PathBuf::new(),
            false,
        ),
        (
            "empty model",
            |config| config.session.model = String::new(),
            false,
        ),
        (
            "rollover without children",
            |config| {
                config.rollover =
                    Some(RolloverRuntimeConfig::new(RolloverPolicy::default()).unwrap());
            },
            false,
        ),
    ];
    for (name, break_it, scope_binding) in rows {
        let mut config = valid.clone();
        break_it(&mut config);
        let error = config.validate().expect_err(name);
        if scope_binding {
            assert!(
                matches!(error, BridgeError::ScopeBinding { .. }),
                "{name}: {error}"
            );
        } else {
            assert!(
                matches!(error, BridgeError::Config { .. }),
                "{name}: {error}"
            );
        }
    }
}
