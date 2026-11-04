use super::*;

use std::path::Path;

#[test]
fn check_config_only_accepts_a_strict_config_without_registry_or_state() {
    use clap::Parser as _;
    let fixture = tempfile::TempDir::new().expect("temporary directory");
    let config_path = fixture.path().join("odind.toml");
    std::fs::write(
        &config_path,
        crate::test_fixture::fixture_config_text(
            fixture.path(),
            &fixture.path().join("snapshot.json"),
        ),
    )
    .expect("write fixture config");
    // Leave declared paths absent to catch accidental registry or state access.
    run(Cli::parse_from([
        "odind",
        "check",
        "--config-only",
        "--config",
        config_path.to_str().expect("utf-8 config path"),
    ]))
    .expect("config-only check succeeds without registry or state");
}


/// A config declaring one `[models]` lane, without touching registry or
/// state: the rendered-gateway scope only reads the config and the file.
fn config_with_declared_lane(root: &Path) -> odin_huginn::OdindConfig {
    let mut config = odin_huginn::OdindConfig::parse(&crate::test_fixture::fixture_config_text(
        root,
        &root.join("snapshot.json"),
    ))
    .expect("fixture config");
    config.models.lanes.insert(
        "goat-flash".to_owned(),
        odin_huginn::OdindModelLaneConfig {
            seats: true,
            strengths: "Cheap and quick".to_owned(),
            tier: Some("fast-cheap".to_owned()),
            display_name: "Goat Flash".to_owned(),
            context_window: 1_048_576,
            cost: odin_huginn::OdindModelCost {
                input: "0".to_owned(),
                output: "0".to_owned(),
            },
            billing: "subscription".to_owned(),
        },
    );
    config
}

/// The rendered `litellm.yaml` as the deploy hands it to the check, in
/// block style with the account windows on their own line so a refusal can
/// drop exactly that line.
fn rendered_gateway(with_windows: bool) -> String {
    format!(
        "model_list:\n\
         \x20 - model_name: goat-flash\n\
         \x20   litellm_params: {{model: commandcode/goat-flash, api_key: os.environ/GOAT_API_KEY}}\n\
         \x20   model_info:\n\
         \x20     odin:\n\
         \x20       account:\n\
         \x20         id: commandcode-goat\n\
         \x20         provider: Command Code\n\
         \x20         billing: subscription\n\
         \x20         monthly_usd: 10\n\
         \x20         renews: null\n\
         \x20         secret: COMMANDCODE_API_KEY\n\
         \x20         keyed: true\n{}\
         \x20       tier: everyday\n\
         \x20       vision: false\n\
         \x20       context_window: 1048576\n\
         router_settings:\n\
         \x20 fallbacks: []\n\
         general_settings:\n\
         \x20 master_key: os.environ/LITELLM_MASTER_KEY\n",
        if with_windows {
            "          windows: [{span: 5h, usd: 14, requests: null}]\n"
        } else {
            ""
        }
    )
}

#[test]
fn check_accepts_a_rendered_gateway_serving_the_declared_lanes() {
    let fixture = tempfile::TempDir::new().expect("temporary directory");
    let rendered = fixture.path().join("litellm.yaml");
    std::fs::write(&rendered, rendered_gateway(true)).expect("write rendered config");
    let config = config_with_declared_lane(fixture.path());
    super::check_rendered_gateway(&config, &rendered)
        .expect("the rendered config serves the declared lane");
}
